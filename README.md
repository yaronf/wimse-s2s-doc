# WIMSE Example Generator

Minimal code to generate examples for the WIMSE Internet-Drafts:

- **draft-ietf-wimse-http-signature**: HTTP Message Signatures for Workload Identity
- **draft-ietf-wimse-s2s-protocol**: Workload Identity Token (WIT) specification
- **draft-sheffer-wimse-fast-httpsig** (optional, `--fast`): handshake + session MAC examples

This is **not** reference code for anything. It's purely for generating examples that appear in the Internet-Drafts.

## What it does

This program generates:
1. **Workload Identity Tokens (WITs)** - JWTs with proof-of-possession binding via the `cnf` claim
2. **HTTP Message Signatures** - RFC 9421-based signatures with WIMSE extensions:
   - The `"wimse-workload-to-workload"` signature tag
   - Signing of `Workload-Identity-Token` headers
   - JWS format signatures using Ed25519 and ES256 keys (RFC 9864 algorithm names)
3. Two example exchanges:
   - **Ed25519**: svcA → svcB (`GET`, no body)
   - **ES256**: svcB → svcC (`POST` with JSON body and `Content-Digest`)
4. With `--fast`, also a fast-httpsig handshake (DHKEM + base-profile JWS) and a first session request/response (HMAC-SHA256), using opaque ticket placeholders (not AEAD).

## Usage

```bash
# Generate base examples and write to files in the 'out' directory
go run .

# Also generate fast-httpsig handshake + session examples
go run . --fast

# Generate examples and print to stdout
go run . --stdout

# Debug: decoded WITs; with --fast also prints suite and session_id
go run . --stdout --debug
go run . --fast --debug
```

### Output Files

By default (without `--stdout`), the program writes to these files in the `out` directory:

- `sigs-request.txt` - Signed request (svcA → svcB, Ed25519)
- `sigs-response.txt` - Signed response (svcB → svcA, Ed25519)
- `sigs-request-b-c.txt` - Signed request (svcB → svcC, Ed25519 caller)
- `sigs-response-c.txt` - Signed response (svcC → svcB, ES256)
- `sigs-svca-jwk.txt` - Service A's JWK (including private key, Ed25519)
- `sigs-svcb-jwk.txt` - Service B's JWK (including private key, Ed25519)
- `sigs-svcc-jwk.txt` - Service C's JWK (including private key, ES256 / P-256)

With `--fast`:

- `fast-hs-request.txt` - Handshake request (WIT + `wimse-kem-suite` / `wimse-kem`)
- `fast-hs-response.txt` - Handshake response (WIT + kem enc + opaque `wimse-ticket-server`)
- `fast-sess-request.txt` - Session request (HMAC, `wimse-httpsig-session`, ticket echo + `wimse-ticket-client`)
- `fast-sess-response.txt` - Session response (HMAC, both tickets echoed)

Tickets are long fixed opaque byte placeholders (64 and 80 octets), not real AEAD.
Sign/verify uses full values; dumped `out/fast-*.txt` files truncate WIT JWTs and ticket
base64 with `...` so draft includes stay readable inline.

### Fast examples are not KEM/KDF test vectors

The `fast-*.txt` dumps are wire examples for draft includes. They expose public
handshake material (`pkR`, `enc`, suite, nonces, WITs) and `session_id`, but not
enough to interop-test DHKEM or the session HKDF on their own.

Missing for test vectors:

- KEM: `skR` (and/or Encap seed / `skE`), plus expected `shared_secret`
- KDF: expected `k_req`, `k_res` (and ideally a fixed transcript + `session_id`)

Without those secrets, a third party cannot Decap, re-derive the MAC keys, or
independently verify the session HMACs. Keys are also regenerated on every run,
and WIT/ticket values in the dumps are ellipsized — fine for includes, not for stable
vectors. If we add vectors later, put them in a separate fixed artifact (for
example `out/fast-test-vectors.json`), not in the include files.

Fast examples need httpsign v0.6.3+ (`[]byte` custom signature parameters and 32-octet HMAC keys).

The `out` directory will be created automatically if it does not exist.

## Related Specifications

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421): HTTP Message Signatures
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864): Fully-Specified Algorithms for JOSE and COSE
- [draft-ietf-wimse-http-signature](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol): WIMSE HTTP Signatures
- [draft-ietf-wimse-s2s-protocol](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol): WIMSE Service-to-Service Protocol
- [draft-sheffer-wimse-fast-httpsig](https://github.com/yaronf/draft-sheffer-wimse-fast-httpsig): Fast HTTP signatures with DHKEM session keys
