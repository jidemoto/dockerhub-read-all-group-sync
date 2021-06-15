FROM golang:alpine

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["dockerhub-read-all-group-sync"]