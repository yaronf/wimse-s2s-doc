# WIMSE Example Generator

Minimal code to generate examples for the WIMSE Internet-Drafts:

- **draft-ietf-wimse-http-signature**: HTTP Message Signatures for Workload Identity
- **draft-ietf-wimse-s2s-protocol**: Workload Identity Token (WIT) specification

This is **not** reference code for anything. It's purely for generating examples that appear in the Internet-Drafts.

## What it does

This program generates:
1. **Workload Identity Tokens (WITs)** - JWTs with proof-of-possession binding via the `cnf` claim
2. **HTTP Message Signatures** - RFC 9421-based signatures with WIMSE extensions:
   - The `"wimse-workload-to-workload"` signature tag
   - Signing of `Workload-Identity-Token` headers
   - JWS format signatures using Ed25519 keys
3. Example HTTP requests and responses demonstrating the complete flow

## Usage

```bash
# Generate examples and write to files in the 'out' directory
# (automatically creates 'out' directory if needed)
go run main.go

# Generate examples and print to stdout
go run main.go --stdout

# Generate examples with debug output showing decoded WITs (stdout only)
go run main.go --stdout --debug
```

### Output Files

By default (without `--stdout`), the program writes to these files in the `out` directory:
- `sigs-request.txt.out` - HTTP request with message signature
- `sigs-response.txt.out` - HTTP response with message signature  
- `sigs-svca-jwk.txt` - Service A's JWK (including private key)
- `sigs-svcb-jwk.txt` - Service B's JWK (including private key)

The `out` directory will be created automatically if it doesn't exist.

## Related Specifications

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421): HTTP Message Signatures
- [draft-ietf-wimse-http-signature](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol): WIMSE HTTP Signatures
- [draft-ietf-wimse-s2s-protocol](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol): WIMSE Service-to-Service Protocol