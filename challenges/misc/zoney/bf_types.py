#!/usr/bin/env python3
import subprocess

SERVER = "52.59.124.14"
PORT = "5054"
DOMAIN = "flag.ctf.nullcon.net"

types = [
    "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SOA", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK", "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB", "HTTPS", "SPF", "UINFO", "UID", "GID", "UNSPEC", "NID", "L32", "L64", "LP", "EUI48", "EUI64", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY", "URI", "CAA", "AVC", "DOA", "AMTRELAY", "TA", "DLV"
]

for t in types:
    try:
        cmd = ["dig", f"@{SERVER}", "-p", PORT, "+short", t, DOMAIN]
        output = subprocess.check_output(cmd, timeout=1).decode('utf-8').strip()
        if output:
            print(f"!!! FOUND {t}: {output}")
    except:
        pass
