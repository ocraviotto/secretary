package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// apiType represents the most common json struct to POST (used with http)
type apiType struct {
	Type string `json:"type"`
}

// Label is the representation of the mesos config label
type Label struct {
	Key   string
	Value string
}

// TaskLabels is the list of labels in the single task
type TaskLabels struct {
	Labels []Label
}

// TaskID holds the value in the task_id field
type TaskID struct {
	Value string
}

// MesosTaskResponse holds the task required parameters we need (name, task_id and the list of labels) from the response
type MesosTaskResponse struct {
	ID           TaskID `json:"task_id"`
	Name         string
	State        string
	NestedLabels TaskLabels `json:"labels"`
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
	Name, ID, State string
	DeployKey       *[32]byte
	ServiceKey      *[32]byte
	Labels          map[string]string
}

func parseMesosTask(taskID string, task MesosTaskResponse) (*AppOrTask, error) {
	// Make sure this is our task
	if taskID != task.ID.Value {
		return nil, fmt.Errorf("The provided taskID (%s) does not equal the task definition value (%s)", taskID, task.ID.Value)
	}

	var encodedDeployKey, encodedServiceKey string
	var gotDeployKey, gotServiceKey string
	var parsedLabels map[string]string
	parsedLabels = make(map[string]string)
	// Extract the deploy public key
	for _, label := range task.NestedLabels.Labels {
		// Parse labels
		parsedLabels[label.Key] = label.Value
		// Set deploy/service keys if found
		switch {
		case label.Key == "DEPLOY_PUBLIC_KEY":
			encodedDeployKey = label.Value
			gotDeployKey = "yes"
		case label.Key == "SERVICE_PUBLIC_KEY":
			encodedServiceKey = label.Value
			gotServiceKey = "yes"
		}
	}

	if gotDeployKey == "" {
		return nil, errors.New("Task missing the DEPLOY_PUBLIC_KEY label in its mesos response")
	}
	deployKey, err := pemDecode(encodedDeployKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode the DEPLOY_PUBLIC_KEY label (%s)", err)
	}

	// Extract the optional service public key
	var serviceKey *[32]byte
	if gotServiceKey != "" {
		serviceKey, err = pemDecode(encodedServiceKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode the SERVICE_PUBLIC_KEY label (%s)", err)
		}
	}

	return &AppOrTask{Name: task.Name, State: task.State,
		TaskID: task.ID.Value, DeployKey: deployKey, ServiceKey: serviceKey,
		Labels: parsedLabels}, nil
}

func getMesosTask(taskID string, body []byte) (*AppOrTask, error) {
	// Parse the initial JSON response with all the tasks
	var clusterTasks MesosPostTasksResponse
	err := json.Unmarshal(body, &clusterTasks)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Mesos Tasks JSON response (%s): %s", err, string(body))
	}

	for _, task := range clusterTasks.GetTasks.Tasks {
		if task.ID.Value == taskID {
			return parseMesosTask(taskID, task)
		}
	}

	return nil, fmt.Errorf("Failed to get Task with ID %s from the list of tasks: %s", taskID, clusterTasks.GetTasks.Tasks)
}

func getMesosTasks(mesosLeaderURL string, taskID string) (*AppOrTask, error) {
	// Fetch the list of all running mesos tasks
	jsonGetTasksPayload := apiType{Type: "GET_TASKS"}
	v1api := fmt.Sprintf("%s/api/v1", mesosLeaderURL)
	jsonValue, err := json.Marshal(jsonGetTasksPayload)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse json pay load: %s", err)
	}
	body, err := httpPostJSON(v1api, jsonValue)
	if err != nil {
		return nil, err
	}

	return getMesosTask(taskID, body)
}
