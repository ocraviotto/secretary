package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// OperatorAPIType represents the most common json struct to POST (used with http)
type OperatorAPIType struct {
	Type string `json:"type"`
}

// TaskLabels is the list of labels in the single task
type TaskLabels struct {
	Labels map[string]string
}

// TaskID holds the value in the task_id field
type TaskID struct {
	value string
}

// MesosTaskResponse holds the task required parameters we need (name, tasK_id and the list of labels) from the response
type MesosTaskResponse struct {
	taskID       TaskID
	Name         string
	State        string
	NestedLabels TaskLabels
}

// MesosTasks holds the "get_tasks.tasks" part of the response
type MesosTasks struct {
	Tasks []MesosTaskResponse
}

// MesosPostTasksResponse is the /api/v1 GET_TASKS POST response struct
type MesosPostTasksResponse struct {
	GetTasks MesosTasks `json:"get_tasks"`
}

// MesosTask is the result struct from getMesosTask
type MesosTask struct {
	Name, TaskID, State string
	DeployKey           *[32]byte
	ServiceKey          *[32]byte
	Labels              map[string]string
}

func parseMesosTask(taskID string, task MesosTaskResponse) (*MesosTask, error) {
	// Extract the deploy public key
	encodedDeployKey, ok := task.NestedLabels.Labels["DEPLOY_PUBLIC_KEY"]
	if !ok {
		return nil, errors.New("Task with ID %s is missing the DEPLOY_PUBLIC_KEY label in its mesos response")
	}

	deployKey, err := pemDecode(encodedDeployKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode the DEPLOY_PUBLIC_KEY label (%s)", err)
	}

	// Extract the optional service public key
	encodedServiceKey, ok := task.NestedLabels.Labels["SERVICE_PUBLIC_KEY"]
	var serviceKey *[32]byte
	if ok {
		serviceKey, err = pemDecode(encodedServiceKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode $SERVICE_PUBLIC_KEY (%s)", err)
		}
	}

	return &MesosTask{Name: task.Name, State: task.State,
		TaskID: taskID, DeployKey: deployKey, ServiceKey: serviceKey,
		Labels: task.NestedLabels.Labels}, nil
}

func getMesosTask(mesosLeaderURL, taskID string, body []byte) (*MesosTask, error) {
	// Parse the initial JSON response with all the tasks
	var clusterTasks MesosPostTasksResponse
	err := json.Unmarshal(body, &clusterTasks)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Mesos Tasks JSON response (%s): %s", err, string(body))
	}

	for _, task := range clusterTasks.GetTasks.Tasks {
		if task.taskID.value == taskID {
			return parseMesosTask(taskID, task)
		}
	}

	return nil, fmt.Errorf("Failed to get Task with ID %s from the list of tasks: %s", taskID, clusterTasks.GetTasks.Tasks)
}

func getMesosTasks(mesosLeaderURL string, taskID string) (*MesosTask, error) {
	// Fetch the list of all running mesos tasks
	jsonGetTasksPayload := &OperatorAPIType{Type: "GET_TASKS"}
	v1api := fmt.Sprintf("%s/api/v1", mesosLeaderURL)
	jsonValue, err := json.Marshal(jsonGetTasksPayload)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse json pay load: %s", err)
	}
	body, err := httpPostJSON(v1api, jsonValue)
	if err != nil {
		return nil, err
	}

	return getMesosTask(taskID, taskID, body)
}
