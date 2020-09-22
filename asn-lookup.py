#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" asn-lookup [.py]

This script provides a Unix socket for ASN lookups as a deamon service.
Since the ASN database is expensive to read and to store in RAM, a
centralised makes more sense than local instances in each Squid ASN helper.

Socket path, permissions, et cetera can be specified using the constants
below import section. """

# Import needed packages
import configparser
import ipaddress
import logging
import logging.handlers
import os
import re
import signal
import socket
import sys
import threading
from getpass import getuser
import pyasn

if getuser() == "root" or os.getuid() == 0:
    print("For security purposes, this script must not be executed as root!")
    sys.exit(127)

try:
    CFILE = sys.argv[1]
except IndexError:
    print("Usage: " + sys.argv[0] + " [path to configuration file]")
    sys.exit(127)

ASNDB = None
PID = os.getpid()

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('asn-lookup')
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


def load_asndb(context=None, psignal=None):
    """ Function call: load_asndb()

    This reads the ASN database from given file location, and overwrites
    database object in ASNDB, if any. It will also be called on receiving
    SIGHUP, where it rereads the database again. """

    if context or psignal:
        LOGIT.info("Received %s from %s, reloading ASN database...", psignal, context)

    # pylint does not like this, but there does not seem to be a better
    # and more robust way... :-/
    global ASNDB
    ASNDB = pyasn.pyasn(config["GENERAL"]["ASNDB_PATH"])
    LOGIT.debug("ASN database set up with object '%s'", ASNDB)


def teardown(context=None, psignal=None):
    """ Function call: teardown()

    This does whatever is necessary for clean termination of this script, such
    as removing PID files.
    """

    LOGIT.info("Received %s from %s, terminating...", psignal, context)

    os.remove(config["GENERAL"]["PID_FILE"])
    sys.exit(0)


def resolve_asn(data: str):
    """ Function call: resolve_asn(raw data received from client)

    Substitute function for doing the actual ASN lookup procedure in order to be able
    to prescind from socket modes. It returns None in case invalid input was received,
    0 if no ASN could be found for that IP address, and it's integer value otherwise.
    """

    cleanstring = str(data.decode('utf-8').rstrip())

    # Only check for valid IPv4/IPv6 address if data are not obviously invalid...
    # Lower boundary: 6 bytes (e.g.: 1.2.3.4)
    # Upper boundary: 39 bytes (e.g.: fe80:0000:0000:0000:0000:0000:0000:0001)
    if cleanstring and len(cleanstring) > 6 and len(cleanstring) < 40:
        try:
            ipobject = ipaddress.ip_address(cleanstring)
        except ValueError:
            LOGIT.warning("Received unexpected data for resolving ASN, discarding...")
            ipobject = ""
    else:
        ipobject = ""

    # Discard invalid input (too long/short, garbarge, no IPv4/IPv6 address, ...)
    if not ipobject or not isinstance(ipobject, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        LOGIT.warning("Discarding invalid input (%s bytes) for resolving ASN...", len(data))
        return None

    asn = 0
    if not ipobject.is_global:
        # Do not attempt to lookup private, reserved or otherwise non-routable IP
        # addresses in the ASN database. In order not to break heavily misconfigured
        # web sites operated by braindead IT staff, return 0 instead of an error...
        LOGIT.info("Skipping ASNDB lookup for martian destination '%s', returning zero...", cleanstring)
    else:
        # At this point, we are dealing with valid input.
        # Look up ASN for given IP address...
        try:
            asn = ASNDB.lookup(cleanstring)[0]
            if asn is None:
                asn = 0
        except Exception as error:
            LOGIT.warning("Failed to enumerate ASN for input '%s' (error: %s), returning zero...",
                          cleanstring, error)

    return asn


class SockServ(object):
    """ Genuine socket server class containing everything that is needed
    for building, running and maintaining our local Unix socket. """

    # A completely exploded IPv6 address is 39 bytes long, so setting
    # buffer size to 41 bytes (39 + 2 for CRLF) should be enough...
    bufsize = 41

    def __init__(self):
        if config["GENERAL"]["MODE"] == "unix":
            # Delete orphaned socket file, if any...
            if os.path.exists(config["GENERAL"]["SOCKET_PATH"]):
                LOGIT.info("Deleting orphaned socket file...")
                os.remove(config["GENERAL"]["SOCKET_PATH"])

            LOGIT.debug("Settting up Unix socket @ '%s'  with permissions '%s' ...",
                        config["GENERAL"]["SOCKET_PATH"], config["GENERAL"]["SOCKET_PERMISSIONS"])
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(config["GENERAL"]["SOCKET_PATH"])

            # Set permissions as configured above...
            # XXX: config.getint() crashes while processing octal numbers, which is why
            # we need some manual int() casting here... :-/
            os.chmod(config["GENERAL"]["SOCKET_PATH"], int(config["GENERAL"]["SOCKET_PERMISSIONS"], 8))
            self.sock.listen()

            LOGIT.debug("Successfully created socket, good, now waiting for queries...")

            while True:
                client, addr = self.sock.accept()

                # Set long timeout for socket, as Squid helpers are (hopefully) present
                # over a long time and there is no need to kick them out periodically...
                client.settimeout(864000)

                # Each client gets its own thread assigned...
                threading.Thread(target=self.handleclient, args=(client, addr),
                                 daemon=True).start()

        elif config["GENERAL"]["MODE"] == "udp":
            LOGIT.debug("Setting up UDP socket @ '%s' (port: %s) ...",
                        config["GENERAL"]["UDP_SOCKET_ADDRESS"],
                        config.getint("GENERAL", "UDP_SOCKET_PORT"))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((config["GENERAL"]["UDP_SOCKET_ADDRESS"],
                            config.getint("GENERAL", "UDP_SOCKET_PORT")))

            LOGIT.debug("Successfully created socket, good, now waiting for queries...")

            while True:
                data, client = self.sock.recvfrom(self.bufsize)

                asn = resolve_asn(data)

                if asn is None:
                    self.sock.sendto("Invalid input received.\n".encode("utf-8"), client)
                else:
                    self.sock.sendto(str(asn).encode("utf-8"), client)

    def handleclient(self, client, addr):
        """ Function call: handleclient([SockServ object, client, client's address])

        This function receives IP addresses from a client, enumerates the corresponding
        Autonomous System Number (ASN) and returns it, if any. """

        LOGIT.debug("handleclient(): got connection from client '%s' with address '%s'",
                    client, addr)

        while True:
            # Read data from client...
            try:
                data = client.recv(self.bufsize)

                if not data:
                    LOGIT.debug("No data received from client, possibly broken pipe, bailing...")
                    raise BrokenPipeError
            except socket.timeout:
                # Handle timeouts while reading data...
                LOGIT.info("Timeout on connection to client '%s' with address '%s' exceeded", client, addr)
                client.close()
                break
            except (ConnectionResetError, BrokenPipeError, OSError):
                LOGIT.debug("Connection was reset by client, bailing...")
                client.close()
                break

            asn = resolve_asn(data)

            if asn is None:
                client.send("Invalid input received.\n".encode("utf-8"))
            else:
                client.send(str(asn).encode("utf-8"))


if os.path.isfile(CFILE) and not os.path.islink(CFILE):
    LOGIT.debug("Attempting to read configuration from '%s' ...", CFILE)

    if os.access(CFILE, os.W_OK) or os.access(CFILE, os.X_OK):
        LOGIT.error("Supplied configuration file '%s' is writeable or executable, aborting", CFILE)
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

        if not (os.path.exists(config["GENERAL"]["ASNDB_PATH"]) and os.path.isfile(config["GENERAL"]["ASNDB_PATH"])):
            raise ValueError("ASN database does not exist or is not a file at given path")

        if not config["GENERAL"]["PID_FILE"]:
            raise ValueError("no path to PID file given")

        if config["GENERAL"]["MODE"].lower() == "unix":
            # Check for presence of mandatory Unix socket configuration statements...
            if not config["GENERAL"]["SOCKET_PATH"]:
                raise ValueError("no Unix socket path specified")

            if not config["GENERAL"]["SOCKET_PERMISSIONS"]:
                raise ValueError("no Unix socket permission specified")
            elif not re.match(r"0o6(6|0)0", config["GENERAL"]["SOCKET_PERMISSIONS"]):
                # Catch semantically invalid Unix file permissions or values that do not
                # make sense (socket not writeable for its owner, read-only for certain
                # group, or world-write/-readable)
                raise ValueError("Unix socket permission invalid")

        elif config["GENERAL"]["MODE"].lower() == "udp":
            # Check for presence of mandatory UDP socket configuration statements...
            if not config["GENERAL"]["UDP_SOCKET_ADDRESS"]:
                raise ValueError("no UDP socket IP address speficied")
            elif ipaddress.ip_address(config["GENERAL"]["UDP_SOCKET_ADDRESS"]).is_global:
                raise ValueError("wont bind to publically routable UDP socket address, bailing!")

            if not config["GENERAL"]["UDP_SOCKET_PORT"]:
                raise ValueError("no UDP socket port speficied")
            elif config.getint("GENERAL", "UDP_SOCKET_PORT") < 1024 or config.getint("GENERAL", "UDP_SOCKET_PORT") > 65535:
                raise ValueError("UDP socket port invalid (1024 < port < 65535)")
        else:
            raise ValueError("operating mode " + config["GENERAL"]["MODE"] + " not implemented")

    except (KeyError, ValueError) as error:
        LOGIT.error("Configuration sanity tests failed: %s", error)
        sys.exit(127)

    LOGIT.info("Configuation sanity tests passed, good, processing...")

    # Apply configured logging level to avoid INFO/DEBUG clutter (thanks, cf5cec3a)...
    LOGIT.setLevel({"DEBUG": logging.DEBUG,
                    "INFO": logging.INFO,
                    "WARNING": logging.WARNING,
                    "ERROR": logging.ERROR}[config["GENERAL"]["LOGLEVEL"].upper()])

else:
    LOGIT.error("Supplied configuraion file path '%s' is not a file", CFILE)
    sys.exit(127)

# Write PID to given path. We assume there is no concurrent instance of this script
# running on the same machine and therefore delete existing PID files (orphaned?) if
# necessary.
if os.path.isfile(config["GENERAL"]["PID_FILE"]):
    LOGIT.warning("Removing existing PID file '%s' - orphaned or concurrent script instance running?",
                  config["GENERAL"]["PID_FILE"])
    os.remove(config["GENERAL"]["PID_FILE"])

with open(config["GENERAL"]["PID_FILE"], "w") as fptr:
    LOGIT.debug("Writing PID %s to PID file '%s'", PID, config["GENERAL"]["PID_FILE"])
    fptr.write(str(PID))

# Initially load ASN database, so the script can handle queries straight away...
load_asndb()

# Reload ASN DB on SIGHUP...
signal.signal(signal.SIGHUP, load_asndb)

# Terminate script on SIGTERMs...
signal.signal(signal.SIGTERM, teardown)

# Call socket object for processing helper queries
try:
    SockServ()
except KeyboardInterrupt:
    LOGIT.info("Received KeyboardInterrupt, shutting down...")
    teardown()

# EOF
