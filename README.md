
# TLS 1.2 Client — `TLS_RSA_WITH_AES_128_CBC_SHA` (C++)

 Built a complete TLS 1.2 handshake in C++, hand-crafting records on raw sockets and using OpenSSL solely for RSA/AES/SHA-1.
`TLS_RSA_WITH_AES_128_CBC_SHA` 

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


