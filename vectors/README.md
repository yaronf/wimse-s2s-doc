# Miao WIMSE HTTP-signature test vectors

Harness to review/verify [draft-miao-wimse-http-signature-test-vectors](https://datatracker.ietf.org/doc/draft-miao-wimse-http-signature-test-vectors/)
against [httpsign](https://github.com/yaronf/httpsign) and the WIMSE HTTP-signature profile.

## Testdata

| File | Source |
|------|--------|
| [`testdata/s01-vector-set-v4.md`](testdata/s01-vector-set-v4.md) | Zenodo [DOI 10.5281/zenodo.24203971](https://doi.org/10.5281/zenodo.24203971) v4 |

- Filename on Zenodo: `s01-vector-set-v4-publication-2026-11-13.md`
- Size: 57364 bytes
- MD5: `5df4f19a8a4a7f0ddd0ff792d0f09bc4`
- License: CC-BY-4.0

Automated `curl` of the Zenodo file URL may return HTTP 403; vendor a browser download and re-check the MD5.

The markdown narrative is largely Chinese. The harness ignores prose and drives control flow from ASCII structure, JWKs/WITs, fenced messages/bases, and `机读锚｜` machine-anchor lines.

## What is verified

- Positive message vectors P-01…P-06 (crypto + WIMSE profile checks)
- Message negatives with `kind=negative-message` (literal, regen, or constructed)
- Fixed clock T0 = 1795000000; default verify time T0+60 (overridden per anchor)

## What is skipped

- Behavior probes N-16…N-20, N-22 (`kind=negative-behavior`) — not decidable from a static message
- Observations O-1…O-3 (`kind=observation`)

## Run

```bash
go test ./vectors/ -v
```

This package is separate from the example generator in the repo root (`go run .` / `--fast`).
