```
Signature Size Comparison
======================================================================

Scheme          Size (bytes)  Visualization
──────────────────────────────────────────────────────────
Ed25519              64      █
ECDSA P-256          64      █
RSA-2048            256      ████
RSA-4096            512      ████████
Dilithium2         2420      ██████████████████████████████████████
Dilithium3         3293      ██████████████████████████████████████████████████
Dilithium5         4595      ████████████████████████████████████████████████████████████████

AG♱ Complete:
  Hash (SHA3-256)     32
  HMAC Tag            32
  Ed25519 Sig         64
  Dilithium3 Sig    3293
  Public Keys       1984
  ──────────────────────
  Total            ~5405      (Comprehensive protection)

Trade-off: Larger signatures for quantum resistance + defense-in-depth
======================================================================
```