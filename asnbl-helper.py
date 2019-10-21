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

# Define constants and settings...
# Path to Unix socket provided by asn-lookup [.py]
SOCKETPATH = "temp.sock"
# How many different ASNs per destination are acceptable?
ASDIVERSITYTHRESHOLD = 5
# Respond with "OK" for destinations whose ASNs exceed given
# threshold (useful for simple Fast Flux mitigation)?
BLOCKDIVERSITYEXCEEDINGDST = False
# List of IP/ASN tuples for socket testing purposes
TESTDATA = [("1.1.1.1", 13335),
            ("8.8.8.8", 15169),
            ("10.0.0.1", 0),
            ("127.0.0.1", 0),
            ("2606:4700:10::6814:d673", 13335),
            ("fe80::1", 0)]


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


def check_asn_against_list(asn: int, asnlist=None):
    """ Function call: check_asn_against_list(ASN to be checked, list of ASNs to match against [if any])
    This takes a enumerated ASN - integer only, without the "AS"
    prefix commonly used -, and performs a lookup either against
    a DNS-based ASNBL/ASNWL or a static list. If the latter is used, a
    list of ASNs to match against - probably read from a file - is
    expected.

    This function returns True if an ASN matches, an False if not. """

    fqfailed = True

    if ASNBLDOMAIN:
        # Running in DNS mode...
        for asnbldom in ASNBLDOMAIN:
            try:
                answer = RESOLVER.query((str(asn) + "." + asnbldom), 'A')
            except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                fqfailed = True
            else:
                fqfailed = False

                # Concatenate responses and log them...
                responses = ""
                for rdata in answer:
                    responses = responses + str(rdata) + " "

                LOGIT.warning("ASNBL hit on '%s.%s' with response '%s'",
                              asn, asnbldom, responses.strip())

                break
    else:
        # Running in static list mode...
        if asn in asnlist:
            fqfailed = False

            LOGIT.warning("ASNBL hit on '%s', found in given ASN list",
                          asn)

    # If any of the queries made above was successful, return True
    if fqfailed:
        return False

    return True


# Abort if no arguments are given...
try:
    if not sys.argv[1]:
        print("BH")
        sys.exit(127)
except IndexError:
    print("Usage: " + sys.argv[0] + " ASNBL1 ASNBL2 ASNBLn (each FQDN or path to files)")
    print("Please make sure general settings (path to asn-lookup [.py] socket, et al.) are set correctly.")
    sys.exit(127)

# Test if given arguments are paths or FQDNs...
ASNBLDOMAIN = []
ASNBLFILE = []
ASNLIST = []

for targument in sys.argv[1:]:
    if os.path.exists(targument):
        ASNBLFILE.append(targument)
    elif is_valid_domain(targument):
        ASNBLDOMAIN.append(targument.strip(".") + ".")
    else:
        print("BH")
        sys.exit(127)

# We do not support both DNS and file mode at the same time. If
# it is desired, please consider running two instances of this helper.
if ASNBLDOMAIN and ASNBLFILE:
    print("BH")
    sys.exit(127)
elif ASNBLFILE:
    for singlefile in ASNBLFILE:
        with open(singlefile, "r") as f:
            fbuffer = f.read().splitlines()

            # Convert list entries (usually strings like "ASxxx") into integers
            for singleline in fbuffer:
                # Ignore comments begnning with # or ; (BIND syntax)...
                if not (singleline.startswith("#") or singleline.startswith(";")):
                    parsed = int(singleline.strip("AS").split()[0])

                    ASNLIST.append(parsed)

    LOGIT.info("Successfully read supplied ASN lists, %s entries by now", len(ASNLIST))

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.timeout = 2

# Establish connection to ASN lookup socket...
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(SOCKETPATH)

# Check if ASN lookup script returns valid data...
LOGIT.debug("Connected to asn-lookup [.py] socket, running response tests...")
for ipasntuple in TESTDATA:
    sock.send(str(ipasntuple[0]).encode('utf-8'))
    returndata = int(sock.recv(64))

    if returndata != ipasntuple[1]:
        LOGIT.error("Response test failed for asn-lookup [.py] socket (tuple: %s), aborting",
                    ipasntuple)
        print("BH")
        sys.exit(127)

LOGIT.info("asn-lookup [.py] socket operational - excellent. Waiting for input...")

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

        # Test if any IP address was successfully resolved for given destination...
        if not IPS:
            print("BH")
            continue
    else:
        print("BH")
        continue

    # Enumerate ASN for each IP address in $IPS...
    ASNS = []
    for singleip in IPS:
        try:
            sock.send(str(singleip).encode('utf-8'))
            returnasn = int(sock.recv(64))

            # Do not append failed lookup results (ASN = 0 or empty) or duplicate entries...
            if returnasn and returnasn > 0 and returnasn not in ASNS:
                ASNS.append(returnasn)
        except BrokenPipeError:
            print("BH")
            break

    # Primitive Fast Flux mitigation: If a destination resolves to
    # different IP addresses within too many different ASNs (normally 1-4),
    # it may be considered as C&C/Fast Flux domain.
    #
    # Depending on the configuration set at the beginning of this
    # script, this is ignored or access will be denied.
    if len(ASNS) > ASDIVERSITYTHRESHOLD:
        LOGIT.warning("Destination '%s' exceeds ASN diversity threshold (%s > %s), possibly Fast Flux: %s",
                      QUERYSTRING, len(ASNS), ASDIVERSITYTHRESHOLD, ASNS)

        if BLOCKDIVERSITYEXCEEDINGDST:
            LOGIT.info("Denying access to possible Fast Flux destination '%s'",
                       QUERYSTRING)
            print("OK")
            continue

    # Query enumerated ASNs against specified black-/whitelist sources...
    qfailed = True
    for singleasn in ASNS:
        if check_asn_against_list(singleasn, ASNLIST):
            qfailed = False
            print("OK")
            break

    if qfailed:
        print("ERR")

# EOF
