DNS
===

This evolving work in progress project has the goal of providing components necessary to to flexibly resolve and serve
DNS and MDNS traffic. The intention is to allow small pieces to be used for special purposes if necessary supporting a 
variety of applications from embedded resolution or answering queries to a fully functional standalone server.

Current status
--------------

Basic pieces are in place to resolve DNS records at least known to RFC-1035, plus AAAA records, RFC8482 awareness, SRV
and NSEC records needed for MDNS. Fully recrusive resolution is supported, and if zone data is populated and injected into
the resolver, authoritative data can be answered locally.

Server components could be easily written to support a DNS server functional to circa 1998 specifications.

Interesting features
--------------------

Zone data may be "keyed" to allow different answers depending on the view of the zone. This "key" is usually the interface
name of the query. External views of this data, such as for zone transfers, can not and therefore do not preserve this
multidimentionality and a flat view of the zone from that interface's perpspective is given. The main motivation for this
feature is to support correct MDNS behavior where records may be unique per network interface.

Planned next items
------------------

* MDNS server
* Traditional DNS server
* AXFR/IXFR support
* Dyanmic updates

Further out
-----------

* DNSSEC (reluctantly), at least enough to have authenticated updates
* Not requiring authoritative records to all be in the cache at once, allowing much larger zones to be backed by on disk
  storage
* Flexible and pluggable back ends other than zone file format which may be custom implemented

Why?
----

I have worked on enough ad-hoc MDNS implementations to want one that is easy to understand and can co-exist with all the basic
componented needed for regular DNS as well. My goal is to make the services from a collection of individually useful components,
while trying to allow idiomatic Go interactions.

This project is never intended to replace Go's built-in DNS resolver. If simple DNS resolution against an existing recursive
resolver is all that is needed, this project is not intended to provide any further benefit unless control or inspection of the
low level queries is desired.
