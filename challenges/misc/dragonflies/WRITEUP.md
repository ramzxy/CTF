# DragoNflieS - Writeup

**Points:** 485  
**Solves:** 6

## Challenge Analysis

The challenge provided a DNS server on port 5053.
Hint: "ensure that only internal networks can resolve certain DNS names".
Querying `flag.ctf.nullcon.net` resulted in `FAKEFLAG` when using our IP or localhost (`127.0.0.1`).

## Solution

We needed to spoof the client subnet using ECS (EDNS Client Subnet) to a specific internal IP.
We found the internal IP `10.13.37.1` by solving the **Zoney** challenge (or analyzing its records). `Zoney` (port 5054) had an A record for `flag.ctf.nullcon.net` pointing to `10.13.37.1`.

Querying DragoNflieS with this IP in the subnet option reveals the flag.

```bash
dig @52.59.124.14 -p 5053 TXT flag.ctf.nullcon.net +subnet=10.13.37.1
```

**Flag:** `ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}`
