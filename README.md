DNS
===

This evolving work in progress project has the goal of providing components necessary to to flexibly resolve and serve
DNS and mDNS traffic. The intention is to allow small pieces to be used for special purposes if necessary supporting a 
variety of applications from embedded resolution or answering queries to a fully functional standalone server.

Current status
--------------

Basic pieces are in place to resolve DNS records at least known to RFC-1035, plus AAAA records, RFC8482 awareness, SRV
and NSEC records needed for MDNS. Fully recrusive resolution is supported. Supports updates and notify. Both AXFR and
IXFR zone transfer queries.

Supports EDNS to advertise larger PDUs.

The server module provides the basics to answer queries, and a simple daemon has been written on top of it which handles
primary, secondary, and hint zones.

Has REST server allowing zones to be configured and loaded.

mDNS functionality including a higher level sevice discovery interface and CLI. While not by default, will even using DDNS
to publish services over traditional DNS.

Interesting features
--------------------

Zone data may be "keyed" to allow different answers depending on the view of the zone. This "key" is usually the interface
name of the query. External views of this data, such as for zone transfers, can not and therefore do not preserve this
multidimentionality and a flat view of the zone from that interface's perpspective is given. The main motivation for this
feature is to support correct mDNS behavior where records may be unique per network interface.

Planned next items
------------------

* Better access controls
* High level mDNS resolver interface for general consumption
* Performance work identifying hot spots where we can do better with memory pressure

Further out
-----------

* DNSSEC (reluctantly), at least enough to have authenticated updates
* Not requiring authoritative records to all be in the cache at once, allowing much larger zones to be backed by on disk
  storage

Why?
----

I have worked on enough ad-hoc mDNS implementations to want one that is easy to understand and can co-exist with all the basic
componented needed for regular DNS as well. My goal is to make the services from a collection of individually useful components,
while trying to allow idiomatic Go interactions.

This project is never intended to replace Go's built-in DNS resolver. If simple DNS resolution against an existing recursive
resolver is all that is needed, this project is not intended to provide any further benefit unless control or inspection of the
low level queries is desired.

This project can be handy for programs wanting to embed DNS services or use mDNS.
