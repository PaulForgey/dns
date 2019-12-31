#!/bin/sh
GOOS=linux GOARCH=amd64 go build . || exit $?
docker build -t tessier-ashpool.net/ns .

