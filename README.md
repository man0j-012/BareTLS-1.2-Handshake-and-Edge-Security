
# TLS 1.2 Client — Prefers `TLS_RSA_WITH_AES_128_CBC_SHA` (C++)

**What this is:** A tiny, from-scratch C++ demo that opens a TLS 1.2 client
connection with OpenSSL and *prefers* the legacy cipher suite
`TLS_RSA_WITH_AES_128_CBC_SHA` for educational purposes, then performs a simple
HTTP/1.1 GET and prints the response.

> ⚠️ Many servers have disabled this legacy suite. If negotiation fails, OpenSSL
> will select another TLS 1.2 suite that's mutually supported. You can change
> the target host or cipher list in `main.cpp`.

## Build

```bash
mkdir build && cd build
cmake ..
make
```

## Run

```bash
# Defaults:
#   host = api.binance.com
#   port = 443
#   Host header = api.binance.com
./tls12_rsa_aes128cbc_sha

# Or specify arguments:
./tls12_rsa_aes128cbc_sha <host-or-ip> <port> [host-header]
```

Examples:

```bash
# Connect by DNS and use the same Host header (SNI + Host will match)
./tls12_rsa_aes128cbc_sha api.binance.com 443 api.binance.com
```

If you connect by IP to a CDN edge and need a different Host header, pass it as
the third argument.

## Notes

- Forces TLS **1.2** only (not 1.3) via `SSL_CTX_set_min/max_proto_version`.
- Sets an OpenSSL cipher list that **prefers RSA/AES128/CBC/SHA1**. If unsupported,
  handshake will use another TLS 1.2 suite. To *require* it, set a strict list like
  `set_cipher_list("RSA+AES128+SHA:!TLSv1.3:!aNULL:!eNULL:@STRENGTH")` and handle failures.
- This demo uses OpenSSL’s high-level TLS stack (safe and compact) rather than
  manually crafting TLS records.
- License: MIT (see below).

## Sample Output (truncated)

```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Content-Length: 28
Connection: close
...
{"serverTime":1681556964107}
```

---

## License (MIT)

Copyright (c) 2025 Manoj Myneni

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
