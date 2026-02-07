# Pasty - Writeup

## Analysis

We're given a pastebin service where pastes are protected by cryptographic signatures. The URL format is:

```
view.php?id=<paste_id>&sig=<64_hex_chars>
```

The signature algorithm in `sig.php`:

```php
function _x($a,$b){
    $r='';
    for($i=0;$i<strlen($a);$i++)
        $r.=chr(ord($a[$i])^ord($b[$i]));
    return $r;
}

function compute_sig($d,$k){
    $h=hash('sha256',$d,1);                    // 32-byte hash of data
    $m=substr(hash('sha256',$k,1),0,24);       // 24 bytes from key hash
    $o='';
    for($i=0;$i<4;$i++){
        $s=$i<<3;                               // s = 0, 8, 16, 24
        $b=substr($h,$s,8);                     // 8 bytes from hash
        $p=(ord($h[$s])%3)<<3;                  // p = 0, 8, or 16
        $c=substr($m,$p,8);                     // 8 bytes from key material
        $o.=($i?_x(_x($b,$c),substr($o,$s-8,8)):_x($b,$c));
    }
    return $o;
}
```

## Vulnerability

The signature scheme has a critical weakness: **the key material is reused and recoverable**.

1. The key-derived material `$m` is only **24 bytes**, split into **3 chunks** of 8 bytes each
2. Which chunk is used for each round is determined by `hash(data)[round*8] % 3`
3. For round 0: `output[0:8] = hash(data)[0:8] ⊕ key_chunk`

This means:

```
key_chunk = hash(data)[0:8] ⊕ signature[0:8]
```

By creating multiple pastes until we hit all 3 chunk indices, we can **recover the entire 24-byte key material**.

## Exploitation

### Step 1: Recover Key Chunks

Create pastes and extract key chunks from the first 8 bytes of each signature:

```python
def recover_key_chunks():
    chunks = [None, None, None]
    attempt = 0
    while None in chunks:
        attempt += 1
        paste_id, sig = create_paste(f"recovery_{attempt}")

        h = hashlib.sha256(paste_id.encode()).digest()
        chunk_idx = h[0] % 3  # Which chunk used in round 0

        if chunks[chunk_idx] is None:
            chunks[chunk_idx] = xor_bytes(h[0:8], sig[0:8])

    return chunks[0] + chunks[1] + chunks[2]
```

### Step 2: Forge Signature

With the key material recovered, compute a valid signature for `"flag"`:

```python
def forge_signature(target_id: str, m: bytes) -> bytes:
    h = hashlib.sha256(target_id.encode()).digest()
    o = b''
    for i in range(4):
        s = i * 8
        b = h[s:s+8]
        p = (h[s] % 3) * 8
        c = m[p:p+8]
        if i == 0:
            o += xor_bytes(b, c)
        else:
            o += xor_bytes(xor_bytes(b, c), o[s-8:s])
    return o
```

### Step 3: Get the Flag

```
GET /view.php?id=flag&sig=<forged_signature>
```

## Flag

`ENO{cr3at1v3_cr7pt0_c0nstruct5_cr4sh_c4rd5}`
