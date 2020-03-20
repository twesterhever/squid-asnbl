#!/bin/bash
# reload_asndb [.sh]

set -eu;

# Where to save the converted database (see asn-lookup [.py])?
CONVERTDBFILE="/opt/squid-asnbl/asndb-current.dat";

# Where to seek for the PID file?
PIDFILE="/tmp/squid-asnbl.pid";

# Create temporary directory and change into it...
TEMPDIR="$( mktemp -d )";
cd "${TEMPDIR}";

# Download current database version...
pyasn_util_download.py --latestv46;

# Convert database into desired format and store it at desired location
# (Since download filename differs over time, we assume there is just one
# rib.* file, i.e. rib.20191018.0600.bz2)
pyasn_util_convert.py --single rib.*.bz2 "${CONVERTDBFILE}";

# Send SIGHUP to the PID hopefully mentioned in $PIDFILE, assuming it
# points to the PID of the currently running asn-lookup [.py] instance.
if [ -f "${PIDFILE}" ]; then
  pkill -SIGHUP -F "${PIDFILE}";
fi;

# Clean up temporary directory...
cd;
rm -rf "${TEMPDIR}";

exit 0;

# EOF
