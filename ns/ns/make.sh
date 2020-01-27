#!/bin/sh
GOOS=linux GOARCH=amd64 go build . || exit $?

docker network rm my-dns || true
docker network create --driver=bridge --subnet=192.168.0.0/24 --gateway=192.168.0.1 my-dns

docker build -t tessier-ashpool.net/ns .


