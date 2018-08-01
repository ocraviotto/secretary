package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// DaemonRequest is the request expected by the /v1/decrypt endpoint
// RequestedSecret is the Secret encrypted with master key
// Key is an optional Name (Enva Var key) of RequestedSecret
type DaemonRequest struct {
	AppID, AppVersion, TaskID string
	RequestedSecret           string
	Key                       string
}

// DaemonResponse is the response returned by the /v1/decrypt endpoint
type DaemonResponse struct {
	PlaintextSecret string
}

// DaemonStatusResponse is the response returned by the /v1/status endpoint
type DaemonStatusResponse struct {
	Status string
}

// AppOrTask holds the result struct for Apps and Task returned by getMesosTask or getMarathonApp
type AppOrTask struct {
	Name, ID, Version, TaskID, State string
	DeployKey                        *[32]byte
	ServiceKey                       *[32]byte
	Env                              map[string]string
	Labels                           map[string]string
}

func errorResponse(w http.ResponseWriter, r *http.Request, err interface{}, statusCode int) {
	log.Printf("HTTP %d from %s: %s", statusCode, r.RemoteAddr, err)
	http.Error(w, fmt.Sprintf("%s", err), statusCode)
}

func decryptRequest(at *AppOrTask, masterKey *[32]byte, serviceEnvelope string) (*DaemonRequest, error) {
	// Authenticate with deploy key and decrypt
	body, err := decryptEnvelope(at.DeployKey, masterKey, serviceEnvelope)
	if err != nil {
		return nil, fmt.Errorf("Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (%s))", err)
	}

	// Authenticate with optional service key and decrypt
	if at.ServiceKey != nil {
		body, err = decryptEnvelope(at.ServiceKey, masterKey, string(body))
		if err != nil {
			return nil, fmt.Errorf("Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (%s))", err)
		}
	}

	// Unpack request struct
	var request DaemonRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JSON request (%s)", err)
	}

	if at.Version != "" && at.ID != "" {
		// Validate that appId, appVersion, taskId corresponds to HTTP request params
		// Parse the timestamps identifying app versions as Time to prevent issues with missing "0" when comparing as str
		requestAppVersion, _ := strToTimeRFC3339(request.AppVersion)
		marathonAppVersion, _ := strToTimeRFC3339(at.Version)

		if request.AppID != at.ID || !requestAppVersion.Equal(marathonAppVersion) || request.TaskID != at.TaskID {
			return nil, errors.New("Given appid, appversion or taskid doesn't correspond to HTTP request params (bug or hacking attempt?)")
		}
	} else if request.TaskID != at.TaskID {
		return nil, errors.New("Given taskid doesn't correspond to HTTP request params (bug or hacking attempt?)")
	}
	return &request, nil
}

func verifyAuthorization(at *AppOrTask, request *DaemonRequest) (bool, error) {
	// Verify that encrypted string is present in app config / mesos task definition
	if at.ID != "" && at.Version != "" && len(at.Env) > 0 {
		// If it's a marathon app, we use the old method and check the value belongs to then env in the target
		for _, value := range at.Env {
			if strings.Contains(stripWhitespace(value), request.RequestedSecret) {
				return true, nil
			}
		}
		return false, errors.New("Given secret isn't part of app config (bug or hacking attempt?)")

	} else if len(at.Labels) > 0 && request.Key != "" {
		// if it is a mesos task, we require the env var is passed in the envelope and ALLOWED SECRETS
		// are allowed in the label (we don't have access to the env)

		allowedSecretsVars, ok := at.Labels["ALLOWED_SECRETS_VARS"]
		if !ok {
			return false, errors.New("Given mesos task secret requires the label ALLOWED_SECRETS_VARS set (bug or hacking attempt?)")
		}
		allowedVars := strings.Split(allowedSecretsVars, ",")

		for _, envVarKey := range allowedVars {
			if stripWhitespace(envVarKey) == request.Key {
				return true, nil
			}
		}
		return false, errors.New("Given secret is not in an env var allowed in ALLOWED_SECRETS_VARS (bug or hacking attempt?)")
	}

	return false, errors.New("We cannot verify the requested secret (bug or hacking attempt?)")

}

func encryptResponse(at *AppOrTask, masterKey *[32]byte, plaintext []byte) ([]byte, error) {
	message := DaemonResponse{PlaintextSecret: encode(plaintext)}
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	// Encrypt with service key
	response := string(encoded)
	if at.ServiceKey != nil {
		response, err = encryptEnvelope(at.ServiceKey, masterKey, []byte(response))
		if err != nil {
			return nil, err
		}
	}

	// Encrypt with deploy key
	encrypted, err := encryptEnvelope(at.DeployKey, masterKey, []byte(response))
	if err != nil {
		return nil, err
	}

	return []byte(encrypted), nil
}

func decryptEndpointHandler(marathonURL, mesosLeaderURL string, masterKey *[32]byte, strategy DecryptionStrategy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			errorResponse(w, r, "Expected POST method", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			errorResponse(w, r, "Expected application/x-www-form-urlencoded request body", http.StatusUnsupportedMediaType)
			return
		}

		appID := r.Form.Get("appid")
		appVersion := r.Form.Get("appversion")
		taskID := r.Form.Get("taskid")
		serviceEnvelope := r.Form.Get("envelope")
		log.Printf("Received request from %s (%s, %s) at %s with envelope %s", appID, taskID, appVersion, r.RemoteAddr, ellipsis(serviceEnvelope, 64))

		var at *AppOrTask

		if appID != "" && taskID != "" && appVersion != "" && serviceEnvelope != "" {
			log.Printf("Using marathon at %s for appID %s", marathonURL, appID)
			at, err = getMarathonApp(marathonURL, appID, appVersion, taskID)
			if err != nil {
				errorResponse(w, r, err, http.StatusInternalServerError)
				return
			}

		} else if taskID != "" && serviceEnvelope != "" {
			log.Printf("Using mesos at %s for task with ID %s", mesosLeaderURL, taskID)
			at, err = getMesosTasks(mesosLeaderURL, taskID)
			if err != nil {
				errorResponse(w, r, err, http.StatusInternalServerError)
				return
			}

		} else {
			errorResponse(w, r, errors.New("Expected parameters {appid, appversion, taskid, envelope} missing"), http.StatusBadRequest)
			return
		}

		// Authenticate and decrypt request
		request, err := decryptRequest(at, masterKey, serviceEnvelope)
		if err != nil {
			errorResponse(w, r, err, http.StatusBadRequest)
			return
		}

		// Verify that the secret is actually part of the config or authorized by it
		ok, err := verifyAuthorization(at, request)
		if !ok || err != nil {
			errorResponse(w, r, err, http.StatusUnauthorized)
			return
		}

		// Authenticate with config key and decrypt secret
		plaintext, err := strategy.Decrypt(request.RequestedSecret, request.Key)
		if err != nil {
			errorResponse(w, r, fmt.Errorf("Failed to decrypt plaintext secret, incorrect config or master key? (%s)", err), http.StatusBadRequest)
			return
		}

		encrypted, err := encryptResponse(at, masterKey, plaintext)
		if err != nil {
			errorResponse(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Write([]byte(encrypted))
	}
}

func statusEndpointHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		message := DaemonStatusResponse{Status: "OK"}
		encoded, err := json.Marshal(message)
		if err != nil {
			errorResponse(w, r, fmt.Errorf("Failed to serialize json response (%s)", err), http.StatusInternalServerError)
			return
		}

		w.Write(encoded)
	}
}

func daemonCommand(listenAddress, marathonURL, mesosLeaderURL string, masterKey *[32]byte, tlsCertFile string, tlsKeyFile string, strategy DecryptionStrategy) {
	http.HandleFunc("/v1/decrypt", decryptEndpointHandler(marathonURL, mesosLeaderURL, masterKey, strategy))
	http.HandleFunc("/v1/status", statusEndpointHandler())

	if tlsCertFile != "" && tlsKeyFile != "" {
		log.Printf("Daemon listening on TLS %s", listenAddress)
		log.Fatal(http.ListenAndServeTLS(listenAddress, tlsCertFile, tlsKeyFile, nil))
	} else {
		log.Printf("Daemon listening on %s", listenAddress)
		log.Fatal(http.ListenAndServe(listenAddress, nil))
	}

}
