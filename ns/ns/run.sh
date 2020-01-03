#!/bin/sh
./make.sh || exit $?

PWD=`pwd`

(docker run --rm -p 5310:53/udp -p 5310:53/tcp --network=my-dns --ip=192.168.0.10 -v "$PWD/ns1:/root/db" tessier-ashpool.net/ns) &

echo "letting primary come up"
sleep 5

(docker run --rm -p 5311:53/udp -p 5311:53/tcp --network=my-dns --ip=192.168.0.11 -v "$PWD/ns2:/root/db" tessier-ashpool.net/ns) &

wait

