#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" asn-lookup [.py]

This script provides a Unix socket for ASN lookups as a deamon service.
Since the ASN database is expensive to read and to store in RAM, a
centralised makes more sense than local insances in each Squid ASN helper.

Socket path, permissions, et cetera can be specified using the constants
below import section. """

# Import needed packages
import ipaddress
import logging
import logging.handlers
import os.path
import signal
import socket
import sys
import threading
import pyasn

# Define constants...
SOCKETPATH = "temp.sock"
SOCKETPERMISSIONS = 0o1130
ASNDBPATH = "/home/user/ipasn_20191002.dat"

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('asn-lookup')
LOGIT.setLevel(logging.DEBUG)

if os.path.islink("/dev/log"):
    HANDLER = logging.handlers.SysLogHandler(address="/dev/log")
else:
    HANDLER = logging.StreamHandler(stream=sys.stderr)

LOGIT.addHandler(HANDLER)


def load_asndb():
    """ Function call: load_asndb() """

    asndb = pyasn.pyasn(ASNDBPATH)
    LOGIT.debug("ASN database set up with object '%s'", asndb)

    return asndb


class SockServ(object):
    """ Genuine socket server class containing everything that is needed
    for building, running and maintaining our local Unix socket. """

    def __init__(self):
        # Delete orphaned socket file, if any...
        if os.path.exists(SOCKETPATH):
            LOGIT.info("Deleting orphaned socket file...")
            os.remove(SOCKETPATH)

        LOGIT.debug("Settting up Unix socket @ '%s'  with permissions '%s' ...", SOCKETPATH, SOCKETPERMISSIONS)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(SOCKETPATH)
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

        LOGIT.debug("handleclient(): got connection from client '%s' with address '%s'", client, addr)

        # A completely exploded IPv6 address is 39 bytes long, so setting
        # buffer size to 40 bytes should be enough...
        bufsize = 40

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

            # Discard invalid input from client (too long, too short, garbarge, no IPv4/IPv6 address, ...)
            if not ipobject or not isinstance(ipobject, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                LOGIT.warning("Discarding invalid input (%s bytes) from client...", len(data))
                try:
                    client.send("Invalid input received.\n".encode('utf-8'))
                except BrokenPipeError:
                    # Client has closed connection by now, do not throw an error here...
                    pass

                # Destroy buffers...
                del data
                del cleanstring
                del ipobject

                # ... and terminate connection to this client
                LOGIT.info("Closing connection to misbehaving client '%s' (addr: '%s')", client, addr)
                client.close()
                break

            # At this point, we are dealing with valid input.
            # Look up ASN for given IP address...
            try:
                asn = ASNDB.lookup(cleanstring)[0]
                if asn is None:
                    asn = 0
            except Exception as error:
                LOGIT.warning("Failed to enumerate ASN for input '%s' (error: %s), returning zero...", cleanstring, error)
                asn = 0
            finally:
                client.send(str(asn).encode('utf-8'))


# Reload ASN DB on SIGHUP...
signal.signal(signal.SIGHUP, load_asndb)

# Initially load ASN database, so the script can handle queries straight away...
ASNDB = load_asndb()

# Call socket object for processing helper queries
try:
    SockServ()
except KeyboardInterrupt:
    LOGIT.info("Received KeyboardInterrupt, shutting down...")
    sys.exit(0)

# EOF