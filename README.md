# certpilot-gateway-selfsigned

A [CertPilot](https://github.com/certpilot/certpilot) gateway that signs
certificates with a local CA it generates itself.

Implements [`provider.v1`](https://github.com/certpilot/certpilot-gateway-sdk).

```
docker run --rm -p 9091:9091 ghcr.io/certpilot/gateway-selfsigned:latest
```

## What it is for

Two things, and it is worth being precise because one of them is not
"development".

**Trying CertPilot out.** It needs no account, no credentials and no network, so
the quickstart can issue a real certificate in the time it takes to start a
container.

**Names no public CA will ever sign.** `.internal`, `.local`, a bare hostname, an
RFC 1918 address. Those are not going to a public CA, and the estate that holds
them still expires, still needs rotating, and is exactly the estate that gets
forgotten. A certificate from here is a real certificate with a real expiry that
this system will renew and deploy like any other.

**It is not a PKI.** There is no offline root, no HSM, no revocation, no CRL and
no path length planning. If you need those, you need Vault or a real CA — and a
gateway for it.

## What it does

| | |
|:---|:---|
| Key types | RSA, ECDSA, Ed25519 |
| CSRs | honoured. Supply one and it signs your key |
| Revocation | **no** — reported as `supports_revocation=false` |
| CA info | **no** — reported as `supports_ca_info=false` |

Those last two are reported honestly rather than stubbed, so the core knows not
to offer a revoke button that would do nothing.

## Flags

```
-port              9091
-insecure          serve without TLS. Loopback only
-tls-cert/-tls-key/-tls-ca
```

## Conformance

```
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest \
    -addr localhost:9091 -insecure -domain test.example.com
```

This gateway is the one that can be checked end to end without any external
dependency, so CI runs the full issuance path here — with and without a CSR —
on every pull request.

## Licence

Apache 2.0.
