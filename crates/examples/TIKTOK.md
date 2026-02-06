# TikTok TLSNotary Proof-of-Concept

Cryptographic proofs of TikTok API responses using TLSNotary MPC-TLS.

Proves that data (comments, mentions) came from `www.tiktok.com` and was not
tampered with. The prover and verifier run locally over a duplex channel — no
external notary server required.

## Benchmarks

Measured on a consumer laptop (Ryzen 7, Linux), `--release` build, residential
internet (~50ms to TikTok CDN). Prover and verifier run on the same machine
over an in-memory channel, so these times reflect **computation only** — no
prover-verifier network latency.

| Example | API Endpoint | Response Size | Proof Time | Data Proved |
|---------|-------------|---------------|------------|-------------|
| `tiktok_comments` | `/api/comment/list/` | ~63 KB | **~1.3s** | 18 comments with users, text, likes |
| `tiktok_mentions` | `/api/notice/multi/` | ~1.5 KB | **~1.1s** | Mention notifications for @-tagged user |

### Network overhead estimates

In a real deployment, prover and verifier communicate over the network.
TLSNotary's MPC-TLS protocol requires significant **upload bandwidth from
prover to verifier** ([FAQ](https://tlsnotary.org/docs/faq/)):

- ~25 MB fixed cost per session (MPC setup: oblivious transfer, garbled circuits)
- ~10 MB per 1 KB of outgoing data (MPC encryption of the HTTP request)
- ~40 KB per 1 KB of incoming data (transcript commitment and proof)

For the `tiktok_comments` example (~1 KB request, ~63 KB response):

| Component | Upload Cost |
|-----------|------------|
| Fixed MPC setup | ~25 MB |
| Request encryption (1 KB) | ~10 MB |
| Response proof (63 KB) | ~2.5 MB |
| **Total prover upload** | **~37.5 MB** |

Estimated wall-clock times including network transfer:

| Network | Upload Speed | Est. Total Time |
|---------|-------------|-----------------|
| Local (in-memory) | N/A | ~1.3s |
| Fiber (100 Mbps up) | 12.5 MB/s | ~4s |
| Cable (20 Mbps up) | 2.5 MB/s | ~16s |
| Mobile 5G (30 Mbps up) | 3.75 MB/s | ~11s |

### Key optimizations active

Two TLSNotary optimizations significantly reduce overhead for our use case:

1. **Deferred decryption** (`defer_decryption`, default: on) — Skips expensive
   per-record MPC decryption during the TLS connection. Application data is
   buffered as ciphertext and decrypted locally after connection close. This
   reduces the incoming data overhead from ~10 MB/KB (same as outgoing) down
   to ~40 KB/KB.

2. **Key disclosure** ([PR #1010](https://github.com/tlsnotary/tlsn/pull/1010))
   — When the full transcript is revealed (our case), the prover discloses the
   encryption key instead of generating per-block ZK proofs. The verifier
   re-encrypts the plaintext locally to verify. This eliminates thousands of
   AES garbled circuits from the prove phase (e.g. ~4000 circuits for a 63 KB
   response).

## Setup

1. Open TikTok in a browser with DevTools (F12) -> Network tab
2. Navigate to the relevant page (video comments or Inbox -> Mentions)
3. Find the API request (`comment/list` or `notice/multi`)
4. Save the **URL path+query** to `path.txt`
5. Save the **Cookie header value** to `cookies.txt`

## Run

```bash
# Comments on a specific video
TIKTOK_PATH_FILE=path.txt TIKTOK_COOKIES_FILE=cookies.txt \
  cargo run --release --example tiktok_comments

# Mention notifications (requires authenticated session)
TIKTOK_PATH_FILE=path.txt TIKTOK_COOKIES_FILE=cookies.txt \
  cargo run --release --example tiktok_mentions
```

Add `RUST_LOG=info` for detailed protocol tracing.

## Architecture

```
src/tiktok.rs              Shared proof infrastructure (prover, verifier, config)
tiktok_comments/           Comment list example (display logic only)
tiktok_mentions/           Mention notifications example (with tip detection)
```

The shared module (`src/tiktok.rs`) handles:
- Loading credentials from env vars or files
- URL query parameter encoding (handles TikTok's X-Gnarly/X-Bogus params)
- MPC-TLS prover/verifier setup and execution
- HTTP chunked transfer encoding cleanup
- JSON extraction from TLS transcripts

## What This Proves

The verifier cryptographically confirms:

1. **Server identity** — Data came from `www.tiktok.com` (TLS certificate)
2. **Data authenticity** — Response content was not modified after receipt
3. **Temporal binding** — Proof is tied to a specific TLS session

This does NOT prove the request was made by a specific user — only that the
response from TikTok is authentic.

## Limits

| Parameter | Value | Notes |
|-----------|-------|-------|
| Max request size | 8 KB | Sufficient for TikTok API GET requests |
| Max response size | 128 KB | Covers ~20 comments or notification pages |
