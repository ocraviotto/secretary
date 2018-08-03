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

func TestKeyDecryptionStrategy(t *testing.T) {
	crypto := newKeyDecryptionStrategy(
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	plaintext, err := crypto.Decrypt("ENC[NACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]", "")
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}

func TestKeyEncryptionStrategy(t *testing.T) {
	encryption := newKeyEncryptionStrategy(
		pemRead("./resources/test/keys/master-public-key.pem"),
		pemRead("./resources/test/keys/config-private-key.pem"))

	decryption := newKeyDecryptionStrategy(
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem"))

	envelope, err := encryption.Encrypt([]byte("secret"))
	assert.Nil(t, err)

	plaintext, err := decryption.Decrypt(envelope, "")
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}

func newTestDecryptionStrategy(configKey string, masterKey string) DecryptionStrategy {
	composite := newCompositeDecryptionStrategy()
	composite.Add("KMS", newKmsDecryptionStrategy(newMockKmsClient()))
	composite.Add("NACL", newKeyDecryptionStrategy(pemRead(configKey), pemRead(masterKey)))
	return composite
}

func TestDaemonDecryptionStrategy(t *testing.T) {
	appsResponse, err := ioutil.ReadFile("./resources/test/marathon-apps-response.json")
	assert.Nil(t, err)

	appsResponseNoServiceKey, err := ioutil.ReadFile("./resources/test/marathon-apps-nosvckey.json")
	assert.Nil(t, err)

	appsResponseEncryptedSubString, err := ioutil.ReadFile("./resources/test/marathon-apps-encsubstr.json")
	assert.Nil(t, err)

	versionsResponse, err := ioutil.ReadFile("./resources/test/marathon-versions-response.json")
	assert.Nil(t, err)

	versionsResponseBadServiceKey, err := ioutil.ReadFile("./resources/test/marathon-versions-badsvckey.json")
	assert.Nil(t, err)

	versionsResponseNoServiceKey, err := ioutil.ReadFile("./resources/test/marathon-versions-nosvckey.json")
	assert.Nil(t, err)

	versionsResponseEncryptedSubString, err := ioutil.ReadFile("./resources/test/marathon-versions-encsubstr.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Marathon
	marathon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/apps/demo/webapp" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp2" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponseNoServiceKey))
		case r.URL.Path == "/v2/apps/demo/webapp3" && r.URL.RawQuery == "embed=apps.tasks":
			fmt.Fprintln(w, string(appsResponseEncryptedSubString))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponse))
		case r.URL.Path == "/v2/apps/demo/webapp/versions/2015-11-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponseBadServiceKey))
		case r.URL.Path == "/v2/apps/demo/webapp2/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponseNoServiceKey))
		case r.URL.Path == "/v2/apps/demo/webapp3/versions/2015-12-04T12:25:08.426Z":
			fmt.Fprintln(w, string(versionsResponseEncryptedSubString))
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer marathon.Close()

	// Mesos single response when getting tasks
	mesosResponse, err := ioutil.ReadFile("./resources/test/mesos-get-tasks.json")
	assert.Nil(t, err)

	// Start in-test HTTP server that emulates Mesos operator API for GET_TASKS
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

	// Start secretary daemon
	handler := decryptEndpointHandler(marathon.URL, mesos.URL,
		pemRead("./resources/test/keys/master-private-key.pem"),
		newTestDecryptionStrategy(
			"./resources/test/keys/config-public-key.pem",
			"./resources/test/keys/master-private-key.pem"))

	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/decrypt":
			handler(w, r)
		default:
			http.Error(w, fmt.Sprintf("Bad URL %s", r.URL.Path), http.StatusNotFound)
		}
	}))

	defer daemon.Close()

	deployPrivateKey, err := pemDecode("8Cw5ysGd14dRObahAX/MtPrkmc7tOVj6OX5lM8HxerI=")
	assert.Nil(t, err)

	appID, appVersion, taskID := "/demo/webapp", "2015-12-04T12:25:08.426Z", "demo_webapp.0f810e10-9a82-11e5-94c7-6a515f434e2d"
	badAppVersion, badTaskID := "2015-11-04T12:25:08.426Z", "demo_webapp.0f844265-9a82-11e5-94c7-6a515f434e2d"
	encryptedSecret := "ENC[NACL,jpDAHM6WZe/1C93FLHd2M916U9AQwjT3VdvzQ7JHTHc57dLXsGE+oI8wDE2Fiw==]"
	kmsSecret := "ENC[KMS,RP+BAwEBCmttc1BheWxvYWQB/4IAAQMBEEVuY3J5cHRlZERhdGFLZXkBCgABBU5vbmNlAf+EAAEHTWVzc2FnZQEKAAAAGf+DAQEBCVsyNF11aW50OAH/hAABBgEwAABw/4IBLFExUHVXdEIxRTdGMXNMcHZmQkdqTCtadUgrZlNDT3ZNRHFUeVJRRTRHVGc9ARgr/502fv/vQP+S/5H/k//gOf/gWDNh/53/3in/uf/L/5r/mTxbARYoewY+qb+skiPKwGUnT/2GADtui80vAA==]"

	// Test Marathon decryption with both deploy and service keys
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))

		plaintext, err = crypto.Decrypt(kmsSecret, "")
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Marathon decryption of a secret that is in a substring in the app config
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			"/demo/webapp3", appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		fmt.Println(err)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Marathon decryption of a multi-line block
	{
		encryptedKey := "ENC[NACL,egFSuFDkZxsmv9w7bWyZyxCBQQeykctG2H6UTiK7EHRdQI3E3NsZBP84Gqy8c5kh8BYErki6F0eqKAxd3u/QcOuMD17YgqTGiE/PMlO75yCuBzCnZNW7Y4b5Ww03v6uo1Fr/ew==]"

		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedKey, "")
		assert.Nil(t, err)
		assert.Equal(t, "123456789012345678901234567890123456789012345678901234567890", string(plaintext))
	}

	// Test Marathon without a service key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			"/demo/webapp2", appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Marathon with a secret that's correct but not part of config
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			"/demo/webapp2", appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(
			"ENC[NACL,Gk0NEy/PBF/949bR/lht1nsI09wYKkY0JOIjW9NFZFG6NTasF00OSWDRA1jA9eRjSR2/0xVCMEKoTou1PGcHSOmvFJGa71GScsI04nan/ZL2c9oeAt//mavWJlOuRokq1grdc3RVk0pwpFnzdLd2gaQW]",
			"")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 401 Error: Given secret isn't part of app config (bug or hacking attempt?))", err.Error())
	}

	// Test Marathon decryption with bad deploy key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			pemRead("./resources/test/keys/bad-private-key.pem"),
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test Marathon decryption with bad service key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/bad-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test Marathon with a bad master key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			"/demo/webapp", appVersion, taskID,
			pemRead("./resources/test/keys/bad-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test Marathon with a bad service key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, badAppVersion, badTaskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using service and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test Marathon with an appVersion and taskId mismatch
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, badTaskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 500 Error: Given taskId is not running (bug or hacking attempt?))", err.Error())
	}

	// Test Marathon with a bad config public key
	handler = decryptEndpointHandler(marathon.URL, mesos.URL,
		pemRead("./resources/test/keys/master-private-key.pem"),
		newTestDecryptionStrategy(
			"./resources/test/keys/bad-public-key.pem",
			"./resources/test/keys/master-private-key.pem"))

	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to decrypt plaintext secret, incorrect config or master key? (Failed to decrypt (incorrect keys?)))", err.Error())
	}

	// Test Marathon with a bad master private key
	handler = decryptEndpointHandler(marathon.URL, mesos.URL,
		pemRead("./resources/test/keys/bad-private-key.pem"),
		newTestDecryptionStrategy(
			"./resources/test/keys/config-public-key.pem",
			"./resources/test/keys/master-private-key.pem"))

	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to authenticate/decrypt request using deploy and master key (incorrect master key or hacking attempt? (Failed to decrypt (incorrect keys?))))", err.Error())
	}

	// Test Marathon with a bad master private key
	handler = decryptEndpointHandler(marathon.URL, mesos.URL,
		pemRead("./resources/test/keys/master-private-key.pem"),
		newTestDecryptionStrategy(
			"./resources/test/keys/config-public-key.pem",
			"./resources/test/keys/bad-private-key.pem"))

	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, "")
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 400 Error: Failed to decrypt plaintext secret, incorrect config or master key? (Failed to decrypt (incorrect keys?)))", err.Error())
	}

	// Mesos tests - appID and appVersion have values that resamble metronome tasks
	// but we also test with empty appID and appVersion
	appID, appVersion = "/test-job/20180725075828m0Ezl", "1970-01-01T00:00:00.000Z"
	taskID = "test-job_20180725075828m0Ezl.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	encryptedSecretEnvVarName := "NACL_SECRET"
	kmsSecretEnvVarName := "KMS_SECRET"
	notAllowedEnvVarName := "NOT_ALLOWED_SECRET"
	taskNoServiceKeyID := "test-no-service-key-job.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	taskMissingAllowedSecretsVarID := "test-allowed-vars-missing-job.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"
	taskNonExistingID := "test-non-existing-job.83c2ad68-8fe0-11e8-88f5-b2fbd5835ad5"

	// Reset the handler to good values
	handler = decryptEndpointHandler(marathon.URL, mesos.URL,
		pemRead("./resources/test/keys/master-private-key.pem"),
		newTestDecryptionStrategy(
			"./resources/test/keys/config-public-key.pem",
			"./resources/test/keys/master-private-key.pem"))

	// Test Mesos decryption with both deploy and service keys
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))

		plaintext, err = crypto.Decrypt(kmsSecret, kmsSecretEnvVarName)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Mesos decryption with empty appID and appVersion
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			"", "", taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))

		plaintext, err = crypto.Decrypt(kmsSecret, kmsSecretEnvVarName)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Mesos without a service key
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskNoServiceKeyID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey, nil)

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	// Test Mesos with a not allowed var name decryption
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, notAllowedEnvVarName)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 401 Error: Given secret is not in an env var allowed in ALLOWED_SECRETS_VARS (bug or hacking attempt?))", err.Error())
	}

	// Test Mesos without ALLOWED_SECRETS_VARS
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskMissingAllowedSecretsVarID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 401 Error: Given mesos task secret requires the label ALLOWED_SECRETS_VARS set (bug or hacking attempt?))", err.Error())
	}

	// Test Mesos with not running (not existing) task
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, appVersion, taskNonExistingID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
	}

	// Test Mesos with bad app Version
	{
		crypto := newDaemonDecryptionStrategy(daemon.URL,
			appID, "whatever", taskNonExistingID,
			pemRead("./resources/test/keys/master-public-key.pem"),
			deployPrivateKey,
			pemRead("./resources/test/keys/myservice-private-key.pem"))

		plaintext, err := crypto.Decrypt(encryptedSecret, encryptedSecretEnvVarName)
		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
		assert.Equal(t, "Failed to decrypt using daemon (HTTP 422 Error: Expected appVersion in valid RFC 3339. Wrong format given)", err.Error())
	}

}
