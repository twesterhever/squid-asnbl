# Squid helpers for enumerating ASNs for given IPs/domains and querying them against ASNBLs
This repository contains [Squid](http://www.squid-cache.org/) helper scripts for
enumerating the Autonomous System Number(s) of a given destination and query them
against DNS- or file-based ASN blacklists.

Looking at ASNs becomes handy since some blacklists do list these, but not all of
their IP addresses (most software, in fact, is not capable of ASN-based filtering).
Further, fast-flux C&C domains tend to be spread across multiple ASNs, while legitimate
sites usually only scatter over one to four ASNs. Even further, miscreans might announce
their IP ranges only against their targets, operating C&C servers or sending spam without
being visible to the rest of the internet and exposed to security researchers and
blacklist operators.

At the time of writing, [Spamhaus ASN-DROP](https://www.spamhaus.org/drop/) is the
only ASN-based blacklist publically available.

## asnbl-helper.py
This script takes a destination IP address or domain (which will be resolved into IPs)
and enumerates all ASNs for it. If configured, access is proactively blocked if the ASN
diversity exceeds a given threshold (5 might be a reasonable value), thus introducing a
primitive fast-flux C&C mitigation.

Additionally, this script performs queries against given ASN blacklist (DNS- and/or file-based),
returns `OK` if _any_ enumerated ASN is listed, and `ERR` if none is. Blacklists and their
types are examined from a configuration file, which has to be the first and sole command
line argument for `asnbl-helper.py`.

Sanity checks are executed against given ASNDBs in order to make sure they are operational.
Querying an instance of `asn-lookup.py` via a Unix socket should be suitable for most
users, in case local ASNDBs should be avoided, DNS-based ASNDBs such as `asn.routeviews.org`
or `origin.asn.cymru.com` are supported as well.

Please refer to `example-configurations/asnbl-helper.conf` for a configuration file sample.

In order to work under chrooted Squid instances on BSD, `/usr/bin/env -S python3 -u` needs
to be changed to `/usr/local/bin/python3 -u`.

## asn-lookup.py
This script provides an Unix socket for ASN lookups. It handles IPv4 or IPv6 addresses
and returns the enumerated ASN (0 if this step failed). Since reading and storing the
ASN database is expensive, this script is expected to run as a daemon in background and
provides service for multiple `asnbl-helper.py` instances.

[pyasn](https://pypi.org/project/pyasn/) is required for this script, usually installable
by using `pip3`.

## reload_asndb.sh
This is intended to be executed periodically (e.g. via `cron`) and downloads the current ASN
database from ftp://archive.routeviews.org/, converts it into a suitable format, stores it
at given path and sends a `SIGHUP` to `asn-lookup.py` script so it reloads the new database.

## Example Squid configuration
Define `asnbl-helper.py` as an external Squid helper:
```
external_acl_type asnblhelper children-max=10 children-startup=2 %DST /usr/local/bin/asnbl-helper.py /path/to/asnbl-helper.conf
acl asnbl external asnblhelper
```

The scripts can be used for both blacklisting and whitelisting. In case of blacklisting, just
deny acces to the defined ACL:
```
http_access deny asnbl
```

For usage as a whitelist, choose `allow` instead of `deny` here. (You might want to rename
the ACL into `asnwl` or similar then, as the given example would be misleading.)

## Further Readings
* [Routeviews project home page](http://www.routeviews.org/routeviews/)
* [Corresponding Squid documentation](http://www.squid-cache.org/Doc/config/external_acl_type/)
* [Spamhaus ASN-DROP list](https://www.spamhaus.org/drop/)
