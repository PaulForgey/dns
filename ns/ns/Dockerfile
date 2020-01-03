FROM ubuntu:18.04

EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 5353/udp

COPY ns /root/

VOLUME /root/db

WORKDIR /root/db/

CMD /root/ns -stderr -conf ns.json



