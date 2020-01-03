#!/bin/sh
GOOS=linux GOARCH=amd64 go build . || exit $?

docker network rm my-dns
docker network create --driver=bridge --subnet=192.168.0.0/16 my-dns

docker build -t tessier-ashpool.net/ns .


