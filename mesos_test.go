package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMesosTask(t *testing.T) {
	taskID := "test-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"

	singleTaskJSON, readErr := ioutil.ReadFile("./resources/test/mesos-demo-single-task.json")
	assert.Nil(t, readErr)

	var singleTask MesosTaskResponse
	unmarshalErr := json.Unmarshal(singleTaskJSON, &singleTask)
	assert.Nil(t, unmarshalErr)

	task, err := parseMesosTask(taskID, singleTask)
	assert.Nil(t, err)
	assert.Equal(t, taskID, task.TaskID)
	assert.Equal(t, "20180725075828m0Ezl.test-job", task.Name)
	assert.Equal(t, "ENV_1,ENV_2", task.Labels["ALLOWED_SECRETS_VARS"])
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(task.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(task.ServiceKey[:]))

	// Verify that taskID is checked
	task, err = parseMesosTask("test-bad-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5", singleTask)
	assert.Nil(t, task)
	assert.NotNil(t, err)
}

func TestParseMesosBadTask(t *testing.T) {
	taskID := "test-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"

	// No service key show still be OK
	singleNoServiceTaskJSON, readErr := ioutil.ReadFile("./resources/test/mesos-demo-single-no-service-task.json")
	assert.Nil(t, readErr)

	var noServiceKeyTask MesosTaskResponse
	unmarshalErr := json.Unmarshal(singleNoServiceTaskJSON, &noServiceKeyTask)
	assert.Nil(t, unmarshalErr)

	task, err := parseMesosTask(taskID, noServiceKeyTask)
	assert.Nil(t, err)
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(task.DeployKey[:]))

	// Verify missing deploy key errors
	singleMissingDeployKeyTaskJSON, readErr := ioutil.ReadFile("./resources/test/mesos-demo-single-missing-deploy-key-task.json")
	assert.Nil(t, readErr)

	var badSingleTask MesosTaskResponse
	unmarshalErr = json.Unmarshal(singleMissingDeployKeyTaskJSON, &badSingleTask)
	assert.Nil(t, unmarshalErr)

	_, err = parseMesosTask(taskID, badSingleTask)
	assert.NotNil(t, err)
}

func TestGetMesosTask(t *testing.T) {
	taskID := "test-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	mesosResponse, err := ioutil.ReadFile("./resources/test/mesos-get-tasks.json")
	assert.Nil(t, err)

	task, err := getMesosTask(taskID, mesosResponse)
	assert.Nil(t, err)
	assert.Equal(t, taskID, task.TaskID)
	assert.Equal(t, "20180725075828m0Ezl.test-job", task.Name)
	assert.Equal(t, "NACL_SECRET,KMS_SECRET,ENC_SUBSTRING", task.Labels["ALLOWED_SECRETS_VARS"])
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(task.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(task.ServiceKey[:]))

	// Verify bad responses
	task, err = getMesosTask(taskID, []byte(`{}`))
	assert.NotNil(t, err)

	// Verify bad responses
	task, err = getMesosTask(taskID, []byte(`{"name": "20180725075828m0Ezl.test-job"}`))
	assert.NotNil(t, err)

	// Verify bad responses
	task, err = getMesosTask(taskID, []byte(`%"#¤%"#¤`))
	assert.NotNil(t, err)
}

func TestGetNotRunningMesosTask(t *testing.T) {
	taskID := "test-non-existing-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	mesosResponse, err := ioutil.ReadFile("./resources/test/mesos-get-tasks.json")
	assert.Nil(t, err)

	_, err = getMesosTask(taskID, mesosResponse)
	assert.NotNil(t, err)
}

func TestGetMesosTasks(t *testing.T) {
	taskID := "test-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	mesosResponse, err := ioutil.ReadFile("./resources/test/mesos-get-tasks.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Mesos
	mesos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.EscapedPath() == "/api/v1" && r.Method == "POST":
			decoder := json.NewDecoder(r.Body)
			var t apiType
			decodeErr := decoder.Decode(&t)
			if decodeErr != nil {
				http.Error(w, fmt.Sprintf("Could not decode request %s", r.Body), http.StatusBadRequest)
				break
			}
			if t.Type != "GET_TASKS" {
				http.Error(w, fmt.Sprintf("Type not supported %s", t.Type), http.StatusBadRequest)
				break
			}
			fmt.Fprintln(w, string(mesosResponse))
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer mesos.Close()

	task, err := getMesosTasks(mesos.URL, taskID)
	assert.Nil(t, err)
	assert.Equal(t, taskID, task.TaskID)
	assert.Equal(t, "20180725075828m0Ezl.test-job", task.Name)
	assert.Equal(t, "NACL_SECRET,KMS_SECRET,ENC_SUBSTRING", task.Labels["ALLOWED_SECRETS_VARS"])
	assert.Equal(t, "omO6DSEw/mZDG9NuhyEC4uYbgwwqEivOuX0EqX9+Ql0=", encode(task.DeployKey[:]))
	assert.Equal(t, "kVOhhw2wAJuAofxO7h4EM0xboxGAwnsq9J6fluFY5CQ=", encode(task.ServiceKey[:]))
}
