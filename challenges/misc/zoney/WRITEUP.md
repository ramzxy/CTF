# Zoney - Writeup (In Progress)

**Points:** 431  
**Solves:** 24

## Challenge Analysis

DNS server on port 5054.
Domain: `flag.ctf.nullcon.net`.
Records found:

- `TXT`: "The flag was removed."
- `A`: `10.13.37.1` (Used for DragoNflieS challenge).
- `SOA`: Normal SOA record.
- `NSEC`/`NSEC3`: NXDOMAIN.
- `ANY`: NXDOMAIN.

## Potential leads

- Obscure record types?
- CHAOS class info?
- Zone transfer (AXFR/IXFR) on other zones?
