package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
)

func login(username string, password string) (token sessionCredentials, err error) {
	authBody := authBody{username, password}
	authBodyJson, _ := json.Marshal(authBody)
	resp, err := http.Post("https://hub.docker.com/v2/users/login", "application/json", bytes.NewBuffer(authBodyJson))
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("request failed: %w", err)
	}

	var responseBody authResponseBody
	err = unmarshalResponse(resp, &responseBody)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("unable to unmarshal response: %w", err)
	}
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "csrftoken" {
			return sessionCredentials{responseBody.Token, cookie.Value}, nil
		}
	}

	return sessionCredentials{}, fmt.Errorf("couldn't find csrf cookie value")
}

func unmarshalResponse(response *http.Response, v interface{}) (err error) {
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			zap.L().Sugar().Errorf("unable to close responsebody for request: %v", err)
		}
	}(response.Body)
	respBodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response: %w", err)
	}
	err = json.Unmarshal(respBodyBytes, v)
	if err != nil {
		return fmt.Errorf("unable to unmarshal resopnse: %w", err)
	}
	return nil
}

/*
  Gets repo names for the provided namespace
*/
func getRepos(namespace string, token sessionCredentials) ([]string, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%v/?page_size=200", namespace)

	repoNames := make([]string, 0)
	for url != "" {
		zap.L().Sugar().Infof("Retrieving %v", url)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to create request: %w", err)
		}
		req.Header.Add("Cookie", fmt.Sprintf("token=%v", token.Token))
		req.Header.Add("X-CSRFToken", token.CsrfToken)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve repo listing: %w", err)
		}
		var responseBody repositoryListingBody
		err = unmarshalResponse(resp, &responseBody)
		if err != nil {
			return nil, fmt.Errorf("unable to handle response: %w", err)
		}

		for _, repo := range responseBody.Results {
			repoNames = append(repoNames, repo.Name)
		}
		url = responseBody.Next
	}

	return repoNames, nil
}

func getEnvironmentVariables() (username string, password string, namespace string, readAllGroup string, err error) {
	username = os.Getenv("DOCKERHUB_USERNAME")
	password = os.Getenv("DOCKERHUB_PASSWORD")
	namespace = os.Getenv("DOCKERHUB_NAMESPACE")
	readAllGroup = os.Getenv("DOCKERHUB_READ_ALL_GROUP")
	if len(username) == 0 {
		err = fmt.Errorf("DOCKERHUB_USERNAME unset")
	}
	if len(password) == 0 {
		err = fmt.Errorf("DOCKERHUB_PASSWORD unset")
	}
	if len(namespace) == 0 {
		err = fmt.Errorf("DOCKERHUB_NAMESPACE unset")
	}
	if len(readAllGroup) == 0 {
		err = fmt.Errorf("DOCKERHUB_READ_ALL_GROUP unset")
	}
	return
}

func getDockerhubGroupId(namespace string, groupName string, token sessionCredentials) (id int, err error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/orgs/%v/groups/%v/", namespace, groupName)
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return -1, fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Add("Cookie", fmt.Sprintf("token=%v", token.Token))
	req.Header.Add("X-CSRFToken", token.CsrfToken)
	resp, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("unable to group metadata: %w", err)
	}
	var groupMetadata dockerhubGroup
	err = unmarshalResponse(resp, &groupMetadata)
	if err != nil {
		return -1, fmt.Errorf("unable to read body / unmarshal response: %w", err)
	}

	return groupMetadata.Id, nil
}

func getGroupPermissions(namespace string, groupName string, token sessionCredentials) (repos []string, err error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://hub.docker.com/v2/orgs/%v/groups/%v/repositories/", namespace, groupName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Add("Cookie", fmt.Sprintf("token=%v", token.Token))
	req.Header.Add("X-CSRFToken", token.CsrfToken)
	zap.L().Sugar().Infof("Retrieving %v", url)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve repo listing: %w", err)
	}
	var responseBody []dockerhubGroupPermission
	err = unmarshalResponse(resp, &responseBody)
	if err != nil {
		return nil, fmt.Errorf("unable to handle response: %w", err)
	}

	repoNames := make([]string, len(responseBody))
	for i, repo := range responseBody {
		repoNames[i] = repo.Repository
	}

	return repoNames, nil
}

func addGroupPermission(namespace string, repo string, groupId int, token sessionCredentials) (err error) {
	body := dockerhubAddGroupPermissionBody{GroupId: groupId, Permission: "read"}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("unable to marshal request body: %w", err)
	}
	zap.L().Sugar().Infof("Request body: %v", string(bodyBytes))

	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%v/%v/groups/", namespace, repo)

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("unable to create request to add group permission: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("JWT %v", token.Token))
	req.Header.Add("X-CSRFToken", token.CsrfToken)
	zap.L().Sugar().Infof("Adding repo %v/%v to group %v via %v", namespace, repo, groupId, url)
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to set read access to repo %v: %w", repo, err)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("status code on group permission add: %v", response.StatusCode)
	}

	return nil
}

func main() {
	logger, _ := zap.NewProduction()
	undo := zap.ReplaceGlobals(logger)
	defer undo()

	username, password, namespace, groupName, err := getEnvironmentVariables()
	sugaredLogger := zap.L().Sugar()
	if err != nil {
		sugaredLogger.Fatalf("Required configuration missing: %v", err)
	}

	token, err := login(username, password)
	if err != nil {
		sugaredLogger.Fatalf("Error logging in: %v", err)
	}

	namespaceRepos, err := getRepos(namespace, token)
	if err != nil {
		sugaredLogger.Fatalf("Error retrieving repos: %v", err)
	}
	sugaredLogger.Infof("Namespace repos: %v", namespaceRepos)

	readableRepos, err := getGroupPermissions(namespace, groupName, token)
	if err != nil {
		sugaredLogger.Fatalf("Error retrieving group permissions: %v", err)
	}
	sugaredLogger.Infof("Group readable repos: %v", readableRepos)

	groupId, err := getDockerhubGroupId(namespace, groupName, token)
	if err != nil {
		sugaredLogger.Fatalf("Error retrieving group ID: %v", err)
	}

	//Massage the repo list into a map so that we can take advantage of a boolean value for lookups
	repos := make(map[string]bool)
	for _, v := range readableRepos {
		repos[v] = true
	}

	for _, repo := range namespaceRepos {
		if !repos[repo] {
			err := addGroupPermission(namespace, repo, groupId, token)
			if err != nil {
				sugaredLogger.Errorf("Unable to add read permission to repo %v: %v", repo, err)
			}
		}
	}

	zap.L().Info("Complete!")
}

type authBody struct {
	Username string
	Password string
}

type authResponseBody struct {
	Token string
}

type repositoryListingBody struct {
	Results  []dockerhubRepository
	Count    int
	Next     string
	Previous string
}

type dockerhubRepository struct {
	Name string
}

type dockerhubAddGroupPermissionBody struct {
	GroupId    int    `json:"group_id"`
	Permission string `json:"permission"`
}

type dockerhubGroupPermission struct {
	Repository     string      `json:"repository"`
	RepositoryType interface{} `json:"repository_type"`
	Permission     string      `json:"permission"`
}

type dockerhubGroup struct {
	Id          int
	Name        string
	Description string
}

type sessionCredentials struct {
	Token     string
	CsrfToken string
}
