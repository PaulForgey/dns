#!/bin/sh
GOOS=linux GOARCH=amd64 go build .
docker build -t tessier-ashpool.net/ns .

