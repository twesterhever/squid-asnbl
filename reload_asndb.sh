#!/bin/bash
# reload_asndb [.sh]

set -eu;

# Where to save the converted database (see asn-lookup [.py])?
CONVERTDBFILE="/opt/squid-asnbl/asndb-current.dat";

# Create temporary directory and change into it...
TEMPDIR="$( mktemp -d )";
cd "${TEMPDIR}";

# Download current database version...
pyasn_util_download.py --latestv46;

# Convert database into desired format and store it at desired location
# (Since download filename differs over time, we assume there is just one
# rib.* file, i.e. rib.20191018.0600.bz2)
pyasn_util_convert.py --single rib.*.bz2 "${CONVERTDBFILE}";

# Send SIGHUP to asn-lookup [.py] so new ASN database will be read,
# assuming the lookup script was not renamed and is executed directly
# using the Python3 interpreter:
# user      6800  0.0  5.9 306468 151292 pts/0   S+   11:17   0:00 python3 ./asn-lookup.py
pkill --signal SIGHUP --full --exact "([\\w\\d\\/\\.]*)python3\\s+([\\w\\d\\/\\.]*)asn-lookup.py";

# Clean up temporary directory...
cd;
rm -rf "${TEMPDIR}";

exit 0;

# EOF
