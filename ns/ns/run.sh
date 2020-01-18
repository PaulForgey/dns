#!/bin/sh
function stop()
{
	echo "stopping ns1"
	docker kill ns1
	echo "stopping ns2"
	docker kill ns2
	echo "exiting"
}

trap stop EXIT

./make.sh || exit $?

PWD=`pwd`

(docker run --hostname ns1 --name ns1 --rm -p 5380:5380/tcp -p 5310:53/udp -p 5310:53/tcp --network=my-dns --ip=192.168.0.10 -v "$PWD/ns1:/root/db" tessier-ashpool.net/ns) &

echo "letting primary come up"
sleep 5

(docker run --hostname ns2 --name ns2 --rm -p 5311:53/udp -p 5311:53/tcp --network=my-dns --ip=192.168.0.11 -v "$PWD/ns2:/root/db" tessier-ashpool.net/ns) &

wait
