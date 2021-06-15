# Docker Hub Read Group Sync Util

Makes sure a specified group has "read" access to all repos in a Docker Hub namespace.

## Gotchas

The password must not be an access token.  [The docs say](https://docs.docker.com/docker-hub/access-tokens/): 
> When logged in with an access token, you can’t perform any admin activity on the account, including changing the password.

## Usage

Requires the following environment variables to be set:

|Variable|Description|
|--------|-----------|
|DOCKERHUB_USERNAME|The username of the user to login as (user must be in the organization owner group)|
|DOCKERHUB_PASSWORD|Password of the Docker Hub user|
|DOCKERHUB_NAMESPACE|The namespace / organization to use|
|DOCKERHUB_READ_ALL_GROUP|The group in the namespace to sync repo access to|

This utility was envisioned to be run from a Kubernetes cron job with secrets, but it can be tested via the code
locally by setting the environment variables and then running 
```
go run .
```

Alternatively, from docker by running
```
docker run --rm -it -e DOCKERHUB_READ_ALL_GROUP -e DOCKERHUB_NAMESPACE -e DOCKERHUB_PASSWORD -e DOCKERHUB_USERNAME --name read-all-group-util jidemoto/dockerhub-read-all-group-sync
```
