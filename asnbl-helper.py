#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" asnbl-helper [.py]

Squid helper script for enumerating the ASN (Autonomous System
Number) of an IP address and querying it against a file- or
DNS-based black- or whitelist. If a domain is given, it will be
resolved to its IP addresses, which will then be checked against
the specified black-/whitelist source.

Settings are read from the configuration file path supplied as a
command line argument. """

# Import needed modules...
import configparser
import ipaddress
import logging
import logging.handlers
import os.path
import re
import socket
import sys
from getpass import getuser
import dns.resolver


if getuser() == "root" or os.getuid() == 0:
    print("For security purposes, this script must not be executed as root!")
    sys.exit(127)

try:
    CFILE = sys.argv[1]
except IndexError:
    print("Usage: " + sys.argv[0] + " [path to configuration file]")
    sys.exit(127)

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('squid-asnbl-helper')
LOGIT.setLevel(logging.INFO)

if os.path.islink("/dev/log"):
    HANDLER = logging.handlers.SysLogHandler(address="/dev/log")
else:
    HANDLER = logging.StreamHandler(stream=sys.stderr)
    # There is no additional metadata available when logging to STDERR,
    # so a logging formatter needs to be added here...
    FORMAT = logging.Formatter(fmt="%(asctime)s %(name)s[%(process)d] %(levelname).4s: %(message)s",
                               datefmt="%b %d %H:%M:%S")
    HANDLER.setFormatter(FORMAT)

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

    # Test if chkdomain is an IP address (should not happen here)
    if is_ipaddress(chkdomain):
        return False

    # Allowed characters
    allowedchars = re.compile(r"(?!-)[a-z\d\-\_]{1,63}(?<!-)$", re.IGNORECASE)

    if len(chkdomain) > 255 or "." not in chkdomain:
        # Do not allow domains which are very long or do not contain a dot
        return False

    if chkdomain[-1] == ".":
        # Strip trailing "." if present
        chkdomain = chkdomain[:-1]

    # Check if sublabels are invalid (i.e. are empty, too long or contain
    # invalid characters)
    for sublabel in chkdomain.split("."):
        if not sublabel or not allowedchars.match(sublabel):
            # Sublabel is invalid
            return False

    return True


def build_reverse_ip(ipaddr):
    """ Function call: build_reverse_ip(IP address)

    This function takes an IPv4 or IPv6 address, and converts it so
    a RBL query can performed with. The full DNS query string is then
    returned back."""

    addr = ipaddress.ip_address(ipaddr)

    if addr.version == 6 or addr.version == 4:
        # In this case, we are dealing with an IP address
        rev = '.'.join(addr.reverse_pointer.split('.')[:-2])
        return rev

    # In this case, we are dealing with a martian
    return None


def resolve_addresses(domain: str):
    """ Function call: resolve_address(domain)
    This function takes a domain and enumerates all IPv4 and IPv6
    records for it. They are returned as an array."""

    # Check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # Enumerate IPv6 addresses...
    ip6a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'AAAA'):
            ip6a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    # Enumerate IPv4 addresses...
    ip4a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'A'):
            ip4a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    # Assemble all IP addresses and return them back
    ips = ip6a + ip4a
    return ips


def load_asnbl_file(filepath: str):
    """ Function call: load_asnbl_file(/Path/to/single/ASNBL/file)

    This reads given filename, strips out comments beginning with # or ; ,
    and returns a list of parsed ASNs."""

    with open(filepath, "r") as fhandle:
        fbuffer = fhandle.read().splitlines()

    # Temporary variable to hold list of parsed ASNs from file
    parsedasns = []

    # Convert list entries (usually strings like "ASxxx") into integers
    for singleline in fbuffer:
        # Ignore comments begnning with # or ; (BIND syntax)...
        if not (singleline.startswith("#") or singleline.startswith(";")):
            parsed = int(singleline.strip("AS").split()[0])

            parsedasns.append(parsed)

    return parsedasns


def resolve_asn(ipaddr: str, asndb):
    """ Function call: resolve_asn(IP address to be resolved,
                                   ASNDB [socket or FQDN])
    This function does whatever magic is necessary to resolve the ASN of
    the given IP address. If type(asndb) indicates a socket, we are most likely
    running in combination with a asn-lookup [.py] instance, otherwise, a FQDN
    is assumed and queried via DNS. """

    if isinstance(type(asndb), type(socket.socket)):
        # We are dealing with a socket (exception handling takes place below), determine
        # it's type as Unix and UDP sockets require different send/receive handling...
        if asndb.type == socket.SOCK_STREAM:
            asndb.send(str(ipaddr).encode("utf-8"))
            returnasn = int(asndb.recv(64))
        elif asndb.type == socket.SOCK_DGRAM:
            asndb.sendto(str(ipaddr).encode("utf-8"), asndb.getpeername())
            returnasn = int(asndb.recvfrom(64)[0])

    else:
        # user@work:~> host -t TXT 8.8.8.8.asn.routeviews.org
        # 8.8.8.8.asn.routeviews.org descriptive text "15169" "8.8.8.0" "24"
        answer = RESOLVER.query((str(build_reverse_ip(ipaddr)) + "." + asndb), "TXT")
        returnasn = int(answer[0].to_text().split()[0].strip("\""))

    return returnasn


def asndb_response_tests(testdata: str, asndb):
    """ Function call: asndb_response_tests(response rest data,
                                            ASNDB [socket or FQDN])

    This function asserts the given ASNDB to return expected ASNs for
    given IP addresses in order to be considered operational. It returns
    True if this test succeeds, and False otherwise. """

    tresult = True

    # XXX: Attempt to work around crappy data types from ConfigParser()
    # while trying to keep configuration values as human-readable as possible.
    ctdata = re.sub(r"[\(\),]", "", testdata)
    titerable = iter(ctdata.split())
    ptdata = list(zip(titerable, titerable))

    for stestdata in ptdata:
        LOGIT.debug("Running response test for '%s' against ASNDB '%s' ...",
                    stestdata, asndb)

        returndata = resolve_asn(stestdata[0], asndb)

        if returndata != int(stestdata[1]):
            LOGIT.error("Response test failed for ASNDB '%s' (tuple: %s), aborting",
                        asndb, stestdata)
            tresult = False
            break

    return tresult


def check_asn_against_list(asn: int, querystring: str, asnbldomains: list, asnlist: list):
    """ Function call: check_asn_against_list(ASN to be checked,
                                              queried destination,
                                              list of active DNS-based ASNBLs,
                                              list of ASNs read from file-based ASNBLs)
    This takes an enumerated ASN - integer only, without the "AS"
    prefix commonly used -, and performs a lookup against DNS-based ASNBLs/ASNWL,
    a static list read from file-based ASNBLs, or both.

    This function returns True if an ASN matches, an False if not. Passing
    queried destination is necessary for logging root cause of listing hits. """

    fqfailed = True

    if asnbldomains:
        for asnbldom in asnbldomains:
            try:
                answer = RESOLVER.query((str(asn) + "." + asnbldom), 'A')
            except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                pass
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                LOGIT.warning("ASNBL '%s' failed to answer query for '%s' within %s seconds, returning 'BH'",
                              asnbldom, asn, RESOLVER.lifetime)
                raise
            else:
                fqfailed = False

                # Concatenate responses and log them...
                responses = ""
                for rdata in answer:
                    responses = responses + str(rdata) + " "

                LOGIT.warning("ASNBL hit on '%s.%s' with response '%s'",
                              asn, asnbldom, responses.strip())
                break

    if asnlist:
        if asn in asnlist:
            fqfailed = False

            LOGIT.warning("ASNBL hit on '%s', found in given ASN list (queried destination: '%s')",
                          asn, querystring)

    # If any of the queries made above was successful, return True
    if fqfailed:
        return False

    return True


if os.path.isfile(CFILE) and not os.path.islink(CFILE):
    LOGIT.debug("Attempting to read configuration from '%s' ...", CFILE)

    if os.access(CFILE, os.W_OK) or os.access(CFILE, os.X_OK):
        LOGIT.error("Supplied configuration file '%s' is writeable or executable, aborting", CFILE)
        print("BH")
        sys.exit(127)

    config = configparser.ConfigParser()

    with open(CFILE, "r") as fptr:
        config.read_file(fptr)

    LOGIT.debug("Read configuration from '%s', performing sanity tests...", CFILE)

    # Attempt to read mandatory configuration parameters and see if they contain
    # useful values, if possible to determine.
    try:
        if config["GENERAL"]["LOGLEVEL"].upper() not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            raise ValueError("log level configuration invalid")

        if config.getint("GENERAL", "RESOLVER_TIMEOUT") not in range(2, 20):
            raise ValueError("resolver timeout configured out of bounds")

        if config["GENERAL"]["SOCKET_PATH"] and config["GENERAL"]["SOCKET_PATH"].startswith("unix:/"):
            # XXX: Assume an existing path to be valid for the moment, as sockets are
            # not covered rightly by os.path.isfile() and broken/faulty sockets will
            # hopefully be detected by using socket.connect() afterwards... :-/
            if not os.path.exists(config["GENERAL"]["SOCKET_PATH"]):
                raise ValueError("socket path to asn-lookup [.py] is not a file")
        elif config["GENERAL"]["SOCKET_PATH"] and config["GENERAL"]["SOCKET_PATH"].startswith("udp:"):
            (dst, dpt) = config["GENERAL"]["SOCKET_PATH"].strip("udp:").split(":")
            if ipaddress.ip_address(dst).is_global:
                raise ValueError("UDP socket destination IP is publically routable, security risk, bailing!")

            # Cast destination port to integer (we'll need to do so later anyways...)
            dpt = int(dpt)

            if dpt < 1024 or dpt > 65536:
                raise ValueError("UDP socket destination port out of bounds")
        else:
            # Empty socket path given, check for valid ASNDB FQDN...
            if not is_valid_domain(config["GENERAL"]["ASNDB_FQDN"]):
                raise ValueError("no socket path to asn-lookup [.py] given and ASNDB FQDN is invalid")

        if config.getint("GENERAL", "AS_DIVERSITY_THRESHOLD") not in range(2, 10):
            raise ValueError("ASN diversity threshold configured out of bounds")

        if config.getboolean("GENERAL", "BLOCK_DIVERSITY_EXCEEDING_DESTINATIONS") not in [True, False]:
            raise ValueError("block diversity exceeding destinations configuration invalid")

        if config.getboolean("GENERAL", "BLOCK_SUSPECTED_SELECTIVE_ANNOUNCEMENTS") not in [True, False]:
            raise ValueError("block suspected selective announcements configuration invalid")

        if not config["GENERAL"]["TESTDATA"]:
            raise ValueError("no ASNDB testing data configured")

        for scasnbl in config["GENERAL"]["ACTIVE_ASNBLS"].split():
            if not config[scasnbl]:
                raise ValueError("configuration section for active ASNBL " + scasnbl + " missing")

            if config[scasnbl]["TYPE"].lower() == "dns":
                if not is_valid_domain(config[scasnbl]["FQDN"]):
                    raise ValueError("no valid FQDN given for active ASNBL " + scasnbl)
            elif config[scasnbl]["TYPE"].lower() == "file":
                if not os.path.isfile(config[scasnbl]["PATH"]) or os.path.islink(CFILE):
                    raise ValueError("configured ASNBL file for active ASNBL " + scasnbl +
                                     " is not a file")

                if os.access(config[scasnbl]["PATH"], os.W_OK) or os.access(config[scasnbl]["PATH"], os.X_OK):
                    raise ValueError("configured ASNBL file for active ASNBL " + scasnbl +
                                     " is writeable or executable")
            else:
                raise ValueError("invalid type for active ASNBL " + scasnbl)

    except (KeyError, ValueError) as error:
        LOGIT.error("Configuration sanity tests failed: %s", error)
        print("BH")
        sys.exit(127)

    LOGIT.info("Configuation sanity tests passed, good, processing...")

    # Apply configured logging level to avoid INFO/DEBUG clutter (thanks, cf5cec3a)...
    LOGIT.setLevel({"DEBUG": logging.DEBUG,
                    "INFO": logging.INFO,
                    "WARNING": logging.WARNING,
                    "ERROR": logging.ERROR}[config["GENERAL"]["LOGLEVEL"].upper()])

else:
    LOGIT.error("Supplied configuraion file path '%s' is not a file", CFILE)
    print("BH")
    sys.exit(127)

# Placeholders for ASNBL sources (files, FQDNs) and read contents...
ASNBLDOMAINS = []
ASNBLFILES = []
ASNLIST = []

for scasnbl in config["GENERAL"]["ACTIVE_ASNBLS"].split():
    if config[scasnbl]["TYPE"] == "file":
        ASNBLFILES.append(config[scasnbl]["PATH"])
    elif config[scasnbl]["TYPE"] == "dns":
        ASNBLDOMAINS.append(config[scasnbl]["FQDN"].strip(".") + ".")
    else:
        # This should not happen as invalid ASNBL types were caught before,
        # but we will never know...
        LOGIT.error("Detected invalid type '%s' while processing active ASNBL '%s'. This should not happen, bailing!",
                    config[scasnbl]["TYPE"], scasnbl)
        print("BH")
        sys.exit(127)

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = config.getint("GENERAL", "RESOLVER_TIMEOUT")

LOGIT.info("Running ASNDB response tests...")
if config["GENERAL"]["SOCKET_PATH"]:
    # Determine Socket type (at the time of writing, Unix and UDP sockets are supported...)
    if config["GENERAL"]["SOCKET_PATH"].startswith("unix:/"):
        # Establish connection to ASN lookup socket...
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(config["GENERAL"]["SOCKET_PATH"])
    elif config["GENERAL"]["SOCKET_PATH"].startswith("udp:"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((dst, dpt))
    else:
        LOGIT.error("Failed to connect to asn-lookup [.py] socket: protocol of '%s' is not implemented",
                    config["GENERAL"]["SOCKET_PATH"])
        print("BH")
        sys.exit(127)

    LOGIT.debug("Connected to asn-lookup [.py] socket, running response tests...")

    if asndb_response_tests(config["GENERAL"]["TESTDATA"], sock):
        LOGIT.info("asn-lookup [.py] socket operational - excellent. Waiting for input...")
    else:
        LOGIT.error("asn-lookup [.py] socket response tests failed, aborting")
        print("BH")
        sys.exit(127)
elif not config["GENERAL"]["SOCKET_PATH"] and config["GENERAL"]["ASNDB_FQDN"]:
    asndbfqdn = config["GENERAL"]["ASNDB_FQDN"]
    LOGIT.debug("Running response tests against DNS-based ASNDB '%s' ...", asndbfqdn)

    if asndb_response_tests(config["GENERAL"]["TESTDATA"], asndbfqdn):
        LOGIT.info("ASNDB '%s' operational - excellent. Waiting for input...",
                   asndbfqdn)
    else:
        LOGIT.error("ASNDB '%s' response tests failed, aborting", asndbfqdn)
        print("BH")
        sys.exit(127)
else:
    # Again, this should not happen...
    LOGIT.error("Reached unexpected ASNDB response test condition. This should not happen, bailing!")
    print("BH")
    sys.exit(127)

# Read contents from given ASNBL files...
if ASNBLFILES:
    for singlefile in ASNBLFILES:
        ASNLIST.extend(load_asnbl_file(singlefile))

    LOGIT.info("Successfully read supplied ASN lists, %s entries by now", len(ASNLIST))

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
        IPS = resolve_addresses(QUERYSTRING.strip(".") + ".")

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
        if sock:
            try:
                resolvedasn = resolve_asn(singleip, sock)
            except (BrokenPipeError, ValueError):
                LOGIT.warning("Failed to enumerate ASN for '%s' by using asn-lookup [.py] socket @ '%s'",
                              singleip, sock)
                ASNS = []
                break
        else:
            try:
                resolvedasn = resolve_asn(singleip, config["GENERAL"]["ASNDB_FQDN"])
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                LOGIT.warning("ASNDB '%s' failed to answer query for '%s' within %s seconds",
                              config["GENERAL"]["ASNDB_FQDN"], singleip, RESOLVER.lifetime)
                ASNS = []
                break

        # In case protection against destinations without public AS announcements for their
        # IP addresses is desired, the query will be denied in case ASN = 0 appears in an
        # resolve_asn() return value...
        if resolvedasn == 0:
            LOGIT.warning("Destination '%s' resolves to IP addresses '%s' without corresponding ASN, probably selectively announced",
                          QUERYSTRING, singleip)

        # Do not append failed lookup results (ASN < 0 or empty or not an integer) or
        # duplicate entries as they do not contribute to Fast Flux detection. In order to
        # detect selective announcements, 0 will be preserved, which is considered to be
        # safe in terms of Fast Flux handling as well...
        if isinstance(type(resolvedasn), type(int)) and resolvedasn > -1 and resolvedasn not in ASNS:
            ASNS.append(resolvedasn)

    # Return BH if no ASNs were enumerated by the for loop above...
    if not ASNS:
        print("BH")
        continue

    # Deny access to destinations without public AS announcements for their IP addresses...
    if 0 in ASNS and config.getboolean("GENERAL", "BLOCK_SUSPECTED_SELECTIVE_ANNOUNCEMENTS"):
        LOGIT.info("Denying access to destination '%s' due to suspected selective announcements",
                   QUERYSTRING)
        print("OK")
        continue

    # Primitive Fast Flux mitigation: If a destination resolves to
    # different IP addresses within too many different ASNs (normally 1-4),
    # it may be considered as C&C/Fast Flux domain.
    #
    # Depending on the configuration set at the beginning of this
    # script, this is ignored or access will be denied.
    if len(ASNS) > config.getint("GENERAL", "AS_DIVERSITY_THRESHOLD"):
        LOGIT.warning("Destination '%s' exceeds ASN diversity threshold (%s > %s), possibly Fast Flux: %s",
                      QUERYSTRING, len(ASNS), config["GENERAL"]["AS_DIVERSITY_THRESHOLD"], ASNS)

        if config.getboolean("GENERAL", "BLOCK_DIVERSITY_EXCEEDING_DESTINATIONS"):
            LOGIT.info("Denying access to possible Fast Flux destination '%s'",
                       QUERYSTRING)
            print("OK")
            continue

    # Query enumerated ASNs against specified black-/whitelist sources...
    qfailed = True
    for singleasn in ASNS:
        try:
            if check_asn_against_list(singleasn, QUERYSTRING, ASNBLDOMAINS, ASNLIST):
                qfailed = False
                print("OK")
                break
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            # Return "BH" in case of DNS failures...
            qfailed = False
            print("BH")
            break

    if qfailed:
        print("ERR")

# EOF
