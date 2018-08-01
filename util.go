package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// CommandError is the checked exception thrown on runtime errors
type CommandError struct {
	msg string // description of error
	err error  // inner error
}

func (e *CommandError) Error() string { return e.msg }

// Panics with a message if the given error isn't nil
func check(err error, a ...interface{}) {
	if err != nil {
		var msg string
		if len(a) > 0 {
			msg = fmt.Sprintf("%s (%s)", fmt.Sprintf(a[0].(string), a[1:]...), err)
		} else {
			msg = fmt.Sprintf("%s", err)
		}

		panic(&CommandError{msg, err})
	}
}

// Panics with a message if the given condition isn't true
func assertThat(condition bool, msg string, a ...interface{}) {
	if !condition {
		panic(&CommandError{fmt.Sprintf(msg, a...), nil})
	}
}

// Min value
func min(a int, b int) int {
	if a < b {
		return a
	}

	return b
}

func max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}

func ellipsis(input string, maxLength int) string {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) > maxLength {
		return fmt.Sprintf("%s...", strings.TrimSpace(trimmed[0:max(maxLength-3, 0)]))
	}

	return trimmed
}

func defaults(a ...string) string {
	for _, item := range a {
		if len(item) > 0 {
			return item
		}
	}

	return ""
}

// Strip whitespace from string
func stripWhitespace(a string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}

		return r
	}, a)
}

func httpReadBody(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d Error: %s", response.StatusCode, ellipsis(string(body), 256))
	}

	return body, nil
}

func httpPostForm(url string, values url.Values) ([]byte, error) {
	response, err := http.PostForm(url, values)
	if err != nil {
		return nil, err
	}

	return httpReadBody(response)
}

func httpPostJSON(url string, json []byte) ([]byte, error) {

	response, err := http.Post(url, "application/json", bytes.NewBuffer(json))
	if err != nil {
		return nil, err
	}

	return httpReadBody(response)
}

func httpGet(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	return httpReadBody(response)
}

func strToTimeRFC3339(timestr string) (time.Time, error) {
	rfc3339, err := time.Parse(time.RFC3339, timestr)
	if err != nil {
		return rfc3339, fmt.Errorf("Failed to parse time string (%s) due to error (%s)", timestr, err)
	}
	return rfc3339, nil
}
