#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" asn-lookup [.py]

This script provides a Unix socket for ASN lookups as a deamon service.
Since the ASN database is expensive to read and to store in RAM, a
centralised makes more sense than local instances in each Squid ASN helper.

Socket path, permissions, et cetera can be specified using the constants
below import section. """

# Import needed packages
import ipaddress
import logging
import logging.handlers
import os.path
import signal
import socket
import stat
import sys
import threading
import pyasn

# *** Define constants and settings... ***

# Path to Unix socket provided by this script
SOCKETPATH = "/tmp/squid-asnbl.sock"
# File permissions of socket (default: 660)
SOCKETPERMISSIONS = stat.S_IWUSR | stat.S_IRUSR | stat.S_IWGRP | stat.S_IRGRP
# Path to ASN database to be used
ASNDBPATH = "/opt/squid-asnbl/asndb-current.dat"

ASNDB = None

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('asn-lookup')
LOGIT.setLevel(logging.DEBUG)

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
    ASNDB = pyasn.pyasn(ASNDBPATH)
    LOGIT.debug("ASN database set up with object '%s'", ASNDB)


class SockServ(object):
    """ Genuine socket server class containing everything that is needed
    for building, running and maintaining our local Unix socket. """

    def __init__(self):
        # Delete orphaned socket file, if any...
        if os.path.exists(SOCKETPATH):
            LOGIT.info("Deleting orphaned socket file...")
            os.remove(SOCKETPATH)

        LOGIT.debug("Settting up Unix socket @ '%s'  with permissions '%s' ...",
                    SOCKETPATH, SOCKETPERMISSIONS)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(SOCKETPATH)

        # Set permissions as configured above...
        os.chmod(SOCKETPATH, SOCKETPERMISSIONS)
        self.sock.listen()

        LOGIT.debug("Successfully created socket, good, now waiting for queries...")

        while True:
            client, addr = self.sock.accept()

            # Set long timeout for socket, as Squid helpers are (hopefully) present
            # over a long time and there is no need to kick them out periodically...
            client.settimeout(864000)

            # Each client gets its own tread assigned...
            threading.Thread(target=self.handleclient, args=(client, addr),
                             daemon=True).start()

    def handleclient(self, client, addr):
        """ Function call: handleclient([SockServ object, client, client's address])

        This function receives IP addresses from a client, enumerates the corresponding
        Autonomous System Number (ASN) and returns it, if any. """

        LOGIT.debug("handleclient(): got connection from client '%s' with address '%s'",
                    client, addr)

        # A completely exploded IPv6 address is 39 bytes long, so setting
        # buffer size to 41 bytes (39 + 2 for CRLF) should be enough...
        bufsize = 41

        while True:
            # Read data from client and clean it up afterwards (no trailing newline, decoded)
            try:
                data = client.recv(bufsize)
                cleanstring = str(data.decode('utf-8').rstrip())
            except socket.timeout:
                # Handle timeouts while reading data...
                LOGIT.info("Timeout on connection to client '%s' with address '%s' exceeded", client, addr)
                client.close()
                break
            except (ConnectionResetError, BrokenPipeError):
                LOGIT.debug("Connection was reset by client, bailing...")
                client.close()
                break

            # Only check for valid IPv4/IPv6 address if data are not obviously invalid...
            # Lower boundary: 6 bytes (e.g.: 1.2.3.4)
            # Upper boundary: 39 bytes (e.g.: fe80:0000:0000:0000:0000:0000:0000:0001)
            if data and cleanstring and len(cleanstring) > 6 and len(cleanstring) < 40:
                try:
                    ipobject = ipaddress.ip_address(cleanstring)
                except ValueError:
                    LOGIT.warning("Received unexpected data from client, discarding...")
                    ipobject = ""
            else:
                ipobject = ""

            # Discard invalid input (too long/short, garbarge, no IPv4/IPv6 address, ...)
            if not ipobject or not isinstance(ipobject, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                LOGIT.warning("Discarding invalid input (%s bytes) from client...", len(data))
                try:
                    client.send("Invalid input received.\n".encode('utf-8'))
                except BrokenPipeError:
                    # Client has closed connection by now, do not throw an error here...
                    pass

                # Destroy buffers and skip further procession of this input...
                del data
                del cleanstring
                del ipobject
                continue

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
                    LOGIT.warning("Failed to enumerate ASN for input '%s' (error: %s), returning zero...", cleanstring, error)

            client.send(str(asn).encode('utf-8'))


# Initially load ASN database, so the script can handle queries straight away...
load_asndb()

# Reload ASN DB on SIGHUP...
signal.signal(signal.SIGHUP, load_asndb)

# Call socket object for processing helper queries
try:
    SockServ()
except KeyboardInterrupt:
    LOGIT.info("Received KeyboardInterrupt, shutting down...")
    sys.exit(0)

# EOF
