# Squid helpers for enumerating ASNs for given IP addresses/domains and querying them against ASNBLs
This repository contains [Squid](http://www.squid-cache.org/) helper scripts for enumerating the
Autonomous System Number(s) of a given destination and query them against DNS- or file-based blacklists.

Looking at ASNs becomes handy since some blacklists do list these, but not all of their IP addresses
(most software, in fact, is not capable of ASN-based filtering). Further, fast-flux C&C domains tend
to be spread across multiple ASNs, while legitimate sites usually scatter over one to four ASNs.

At the time of writing, [Spamhaus ASN-DROP](https://www.spamhaus.org/drop/) is the only ASN-based blacklist
publically available.

## asn-lookup.py
This script provides an Unix socket for ASN lookups. It handles IPv4 or IPv6 addresses and returns
the enumerated ASN (0 if this step failed). Since reading and storing the ASN database is expensive,
this script is expected to run as a daemon in background and provides service for multiple `asnbl-helper.py`
instances.

[pyasn](https://pypi.org/project/pyasn/) is required for this script, usually installable by using `pip3`.

## asnbl-helper.py
This script takes a destination IP address or domain (which will be resolved into IPs) and enumerates all
ASNs for it. If configured, access is proactively blocked if the ASN diversity exceeds a given threshold
(5 might be a reasonable value), thus introducing a primitive fast-flux C&C mitigation.

Additionally, this script performs queries against given ASN blacklist (either DNS- or file-based, only
one kind is supported at a time), returns `OK` if _any_ enumerated ASN is listed, and `ERR` if none is.
Blacklists are given as command line arguments.

Sanity checks are executed against given Unix socket to `asn-lookup.py` in order to make sure ASN database
is operational (please note IPv6 data will be tested, too).

## reload_asndb.sh
This is intended to be executed periodically (e.g. via `cron`) and downloads the current ASN database from
ftp://archive.routeviews.org/, converts it into a suitable format, stores it at given path and sends a `SIGHUP`
to `asn-lookup.py` script so it reloads the new database.

## Example Squid configuration
Running ASNBL helper using a static ASN blacklist file:
```
external_acl_type asnblhelper children-max=10 children-startup=2 %DST /usr/local/bin/asnbl-helper.py /opt/asnbl/asndrop.txt
acl asnbl external asnblhelper
```
Running ASNBL helper using a DNS-based ASN blacklist:
```
external_acl_type asnblhelper children-max=10 children-startup=2 %DST /usr/local/bin/asnbl-helper.py asnbl.example.com
acl asnbl external asnblhelper
```

## Further Readings
* [Routeviews project home page](http://www.routeviews.org/routeviews/)
* [Corresponding Squid documentation](http://www.squid-cache.org/Doc/config/external_acl_type/)
