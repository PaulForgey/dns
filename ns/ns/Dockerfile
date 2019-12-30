FROM ubuntu:18.04

EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 5353/udp

WORKDIR /root

COPY ns ns.json *.db /root/

CMD /root/ns -stderr -conf /root/ns.json

