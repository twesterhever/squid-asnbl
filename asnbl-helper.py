#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" asnbl-helper [.py]

Squid helper script for enumerating the ASN (Autonomous System
Number) of an IP address and querying it against a file- or
DNS-based black- or whitelist. If a domain is given, it will be
resolved to its IP addresses, which will then be checked against
the specified black-/whitelist source. """

# Import needed modules...
import ipaddress
import logging
import logging.handlers
import os.path
import re
import socket
import sys
import dns.resolver

# Define constants... (ASNLIST may contain a path to an ASN black-/whitelist
# file, or a FQDN for DNSBL usage)
SOCKETPATH = "temp.sock"
ASNLIST = sys.argv[1]

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('squid-asnbl-helper')
LOGIT.setLevel(logging.INFO)

if os.path.islink("/dev/log"):
    HANDLER = logging.handlers.SysLogHandler(address="/dev/log")
else:
    HANDLER = logging.StreamHandler(stream=sys.stderr)

LOGIT.addHandler(HANDLER)


def is_ipaddress(chkinput: str):
    """ Function call: is_ipaddress(input)
    Tests if input is an IP address. It returns True if it
    is one (v4/v6 does not matter), and False if not."""

    try:
        ipaddress.ip_address(chkinput)
        return True
    except ValueError:
        return False


def is_valid_domain(chkdomain: str):
    """ Function call: is_valid_domain(domain name)
    Checks if given domain is valid, i.e. does not contain any
    unspecified characters. It returns True if a domain was valid,
    and False if not."""

    # test if chkdomain is an IP address (should not happen here)
    if is_ipaddress(chkdomain):
        return False

    # allowed characters
    allowedchars = re.compile(r"(?!-)[a-z\d\-\_]{1,63}(?<!-)$", re.IGNORECASE)

    if len(chkdomain) > 255 or "." not in chkdomain:
        # do not allow domains which are very long or do not contain a dot
        return False

    if chkdomain[-1] == ".":
        # strip trailing "." if present
        chkdomain = chkdomain[:-1]

    # check if sublabels are invalid (i.e. are empty, too long or contain
    # invalid characters)
    for sublabel in chkdomain.split("."):
        if not sublabel or not allowedchars.match(sublabel):
            # sublabel is invalid
            return False

    return True


def resolve_addresses(domain: str):
    """ Function call: resolve_address(domain)
    This function takes a domain and enumerates all IPv4 and IPv6
    records for it. They are returned as an array."""

    # check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # enumerate IPv6 addresses...
    ip6a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'AAAA'):
            ip6a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass

    # enumerate IPv4 addresses...
    ip4a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'A'):
            ip4a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass

    # assemble all IP addresses and return them back
    ips = ip6a + ip4a
    return ips


# Abort if no arguments are given...
try:
    if not sys.argv[1]:
        print("BH")
        sys.exit(127)
except IndexError:
    print("Usage: " + sys.argv[0] + " ASNBL1 ASNBL2 ASNBLn")
    sys.exit(127)

# Test if given arguments are paths or FQDNs....
ASNBLDOMAIN = []
ASNBLFILE = []

for targument in sys.argv[1:]:
    if is_valid_domain(targument):
        ASNBLDOMAIN.append(targument.strip(".") + ".")
    elif os.path.exists(targument):
        ASNBLFILE.append(targument)
    else:
        print("BH")
        sys.exit(127)

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.timeout = 2

# Establish connection to ASN lookup socket...
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(SOCKETPATH)

# Read domains or IP addresses from STDIN in a while loop, resolve IP
# addresses if necessary, and do ASN lookups against specified socket for
# each IP address. Query all specified ASN black-/whitelists afterwards,
# return OK if a ASN hits, or ERR if none was found.
while True:
    try:
        QUERYSTRING = str(sys.stdin.readline().rstrip().split()[0])
    except KeyboardInterrupt:
        sys.exit(127)

    # Abort if no STDIN input was received
    if not QUERYSTRING:
        break

    # Check if input is an IP address or a valid domain, and return "BH"
    # if none matches. In case of domains, resolve corresponding IP addresses
    if is_ipaddress(QUERYSTRING):
        IPS = [QUERYSTRING]
    elif is_valid_domain(QUERYSTRING):
        IPS = resolve_addresses(QUERYSTRING)
    else:
        print("BH")
        continue

    # Enumerate ASN for each IP address in $IPS...
    ASNS = []
    for singleip in IPS:
        try:
            sock.send(str(singleip).encode('utf-8'))
            buf = sock.recv(64)

            ASNS.append(int(buf))
        except BrokenPipeError:
            print("BH")
            break

    # TODO: Debugging code, remove afterwards...
    print(ASNS)

    # Query enumerated ASNs against specified black-/whitelist sources...
    

# EOF
