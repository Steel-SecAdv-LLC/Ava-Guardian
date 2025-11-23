| Operation | Time (μs) | Ops/Second | Signature Size |
|-----------|-----------|------------|----------------|
| SHA3-256 (DNA codes + helix params) | 8.51 | 117,460 | - |
| SHA3-256 (raw, 43 bytes) | 1.00 | 1,004,425 | - |
| HMAC-SHA3-256 (authenticate) | 3.91 | 255,971 | - |
| HMAC-SHA3-256 (verify) | 3.79 | 263,563 | - |
| Ed25519 (keygen) | 62.41 | 16,023 | - |
| Ed25519 (sign) | 73.01 | 13,697 | 64 bytes |
| Ed25519 (verify) | 122.75 | 8,146 | - |
| AG♱ Package Creation (6 layers) | 131.49 | 7,605 | - |
| AG♱ Package Verification (6 layers) | 142.52 | 7,016 | - |