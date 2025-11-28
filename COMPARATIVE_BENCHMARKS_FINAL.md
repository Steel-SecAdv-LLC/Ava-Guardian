# Comparative Performance Benchmarks - Complete Analysis

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.0.0 |
| Test Date | 2025-11-28 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

This document contains **complete comparative performance benchmarks** between Ava Guardian ♱ and other cryptographic implementations, including **hybrid Ed25519 + ML-DSA-65 operations**.

### Implementations Tested

1. **Ava Guardian ♱** - Integrated hybrid Python/Cython implementation with 6-layer defense
2. **cryptography library** - OpenSSL-backed Ed25519 (industry standard)
3. **liboqs-python** - Direct liboqs bindings for ML-DSA-65
4. **OpenSSL + liboqs** - Hybrid implementation using best-of-breed libraries

---

## Critical Findings

### Classical Ed25519 Operations

| Operation | Ava Guardian | OpenSSL | Performance |
|-----------|--------------|---------|-------------|
| **Sign** | 10,027 ops/sec | **20,582 ops/sec** | OpenSSL **2.05x faster** |
| **Verify** | 8,078 ops/sec | 8,391 ops/sec | OpenSSL 1.04x faster (negligible) |

**Conclusion:** OpenSSL is significantly faster for Ed25519 signing due to highly optimized C implementation.

---

### Post-Quantum ML-DSA-65 Operations

| Operation | Ava Guardian | liboqs-python | Performance |
|-----------|--------------|---------------|-------------|
| **Sign** | 9,150 ops/sec | 9,234 ops/sec | **Essentially identical** (0.9% difference) |
| **Verify** | 27,306 ops/sec | 29,478 ops/sec | liboqs 1.08x faster |

**Conclusion:** Ava Guardian's ML-DSA-65 performance is **competitive with pure liboqs**. Within 8% on all operations.

---

### Hybrid Operations (Ed25519 + ML-DSA-65)

**This is the key comparison** - hybrid signatures are Ava Guardian's actual use case.

| Operation | Ava Guardian | OpenSSL+liboqs | Performance |
|-----------|--------------|----------------|-------------|
| **Hybrid Sign** | 4,420 ops/sec | **6,468 ops/sec** | OpenSSL+liboqs **1.46x faster** |
| **Hybrid Verify** | **6,054 ops/sec** | 5,776 ops/sec | Ava Guardian **1.05x faster** |

**Critical Analysis:**

- **Hybrid Signing:** OpenSSL+liboqs is 46% faster (6.5K vs 4.4K ops/sec)
- **Hybrid Verification:** Ava Guardian is 5% faster (6.1K vs 5.8K ops/sec)

**Why the difference?**
- OpenSSL's Ed25519 signing is highly optimized (~2x faster)
- Ava Guardian's overhead comes from Python/Cython layer and additional logic
- For verification, Ava Guardian's optimizations compensate for the wrapper overhead

---

### Full 6-Layer Package Operations

Ava Guardian's **complete package** includes more than just signatures:

| Layer | Component | Overhead |
|-------|-----------|----------|
| 1 | SHA3-256 Content Hash | ~0.001ms |
| 2 | HMAC-SHA3-256 Auth | ~0.004ms |
| 3 | Ed25519 Signature | ~0.100ms |
| 4 | ML-DSA-65 Signature | ~0.109ms |
| 5 | HKDF Key Derivation | ~0.144ms |
| 6 | RFC 3161 Timestamp | (optional) |
| | **Canonical Encoding** | ~0.002ms |
| | **3R Monitoring** | <0.006ms (<2%) |

**Complete Package Performance:**
- **Create:** 3,595 ops/sec (0.278ms) - includes all 6 layers
- **Verify:** 5,029 ops/sec (0.199ms) - includes all 6 layers

**Comparison:**
- Hybrid signatures alone (Ava): 4,420 ops/sec
- Full package (Ava): 3,595 ops/sec
- **Overhead for layers 1, 2, 5, 6:** ~0.05ms (18% additional time)

---

## Detailed Breakdown

### Test Environment

```
OS: Linux 4.4.0 x86_64
CPU: 16 cores
Memory: 13.0 GB
Python: 3.11
liboqs: 0.15.0 (built from source)
Iterations: 1,000 per operation
```

### Individual Operation Performance

#### Ed25519 (Classical)

| Implementation | Sign (ops/sec) | Verify (ops/sec) |
|----------------|----------------|------------------|
| Ava Guardian | 10,027 | 8,078 |
| OpenSSL | **20,582** | **8,391** |
| **Ratio** | **2.05x slower** | 1.04x slower |

#### ML-DSA-65 (Post-Quantum)

| Implementation | Sign (ops/sec) | Verify (ops/sec) |
|----------------|----------------|------------------|
| Ava Guardian | 9,150 | 27,306 |
| liboqs-python | 9,234 | **29,478** |
| **Ratio** | 0.99x (identical) | 1.08x slower |

#### Hybrid (Ed25519 + ML-DSA-65)

| Implementation | Sign (ops/sec) | Verify (ops/sec) |
|----------------|----------------|------------------|
| Ava Guardian | 4,420 | **6,054** |
| OpenSSL+liboqs | **6,468** | 5,776 |
| **Ratio** | **1.46x slower** | **1.05x faster** |

---

## Honest Assessment

### Where Ava Guardian is Slower

✗ **Ed25519 Signing:** 2x slower than OpenSSL (10K vs 21K ops/sec)
✗ **Hybrid Signing:** 1.5x slower than OpenSSL+liboqs (4.4K vs 6.5K ops/sec)
✗ **ML-DSA-65 Verification:** 8% slower than pure liboqs (27K vs 29K ops/sec)

### Where Ava Guardian is Competitive/Faster

✓ **ML-DSA-65 Signing:** Identical to liboqs (<1% difference)
✓ **Hybrid Verification:** 5% faster than OpenSSL+liboqs
✓ **Ed25519 Verification:** Negligible difference vs OpenSSL (4% slower)

### What This Data Actually Means

**For pure speed on hybrid operations:**
- Use OpenSSL+liboqs for maximum hybrid signing performance (1.5x faster)
- Ava Guardian provides competitive hybrid verification (actually slightly faster)

**What this comparison doesn't include:**
1. **6-Layer Defense Architecture** - Only Ava Guardian provides SHA3 + HMAC + Ed25519 + ML-DSA-65 + HKDF + Timestamps
2. **3R Runtime Monitoring** - Security anomaly detection with <2% overhead
3. **Ethical Constraints** - HKDF with ethical context binding
4. **Integrated Key Management** - Complete KMS with ~2ms full generation time
5. **Cross-platform Consistency** - Same codebase for Linux/macOS/Windows/ARM64

---

## Performance vs Security Trade-offs

### Use OpenSSL + liboqs when:
- ✓ You need maximum hybrid signing speed (6.5K vs 4.4K ops/sec)
- ✓ You only need Ed25519 + ML-DSA-65 signatures
- ✓ You're implementing your own defense-in-depth layers
- ✓ You don't need runtime security monitoring

### Use Ava Guardian when:
- ✓ You need 6-layer defense-in-depth (SHA3 + HMAC + dual signatures + HKDF + timestamps)
- ✓ You want runtime security monitoring (3R) with <2% overhead
- ✓ You need integrated key management and ethical constraints
- ✓ Competitive hybrid verification performance is acceptable (actually faster)
- ✓ 4.4K hybrid signs/sec is sufficient for your use case

---

## Answering "Is It The Fastest?"

**For individual operations:**
- ❌ Ed25519: No, OpenSSL is 2x faster
- ✓ ML-DSA-65: Yes, competitive with liboqs (<1% difference)
- ❌ Hybrid Sign: No, OpenSSL+liboqs is 1.5x faster
- ✓ Hybrid Verify: Yes, 5% faster than OpenSSL+liboqs

**For complete hybrid PQC packages:**
- ❌ Not the fastest for hybrid signing (but 4.4K ops/sec is production-ready)
- ✓ Fastest for hybrid verification among tested implementations
- ✓ **Only implementation** with 6-layer defense + 3R monitoring + ethical constraints

**Bottom line:** Ava Guardian prioritizes **comprehensive security** over raw speed, while maintaining **competitive performance** (within 1.5x of best-of-breed libraries for hybrid operations).

---

## Raw Benchmark Data

Complete results available in: `benchmarks/comparative_benchmark_results.json`

**Key Performance Metrics:**

```json
{
  "Ava Guardian Hybrid Sign": "4,420 ops/sec (0.2262ms)",
  "OpenSSL+liboqs Hybrid Sign": "6,468 ops/sec (0.1546ms)",
  "Slowdown Factor": "1.46x",

  "Ava Guardian Hybrid Verify": "6,054 ops/sec (0.1652ms)",
  "OpenSSL+liboqs Hybrid Verify": "5,776 ops/sec (0.1731ms)",
  "Speedup Factor": "1.05x (Ava Guardian faster)"
}
```

---

## Conclusion

Ava Guardian **is NOT the fastest** for all operations, but it **IS competitive** while providing significantly more security features:

- **Hybrid Signing:** 1.5x slower than OpenSSL+liboqs (but still 4.4K ops/sec)
- **Hybrid Verification:** Actually faster than OpenSSL+liboqs (6.1K vs 5.8K ops/sec)
- **ML-DSA-65 Operations:** Competitive with pure liboqs (within 8%)
- **Complete Package:** Unique 6-layer defense + 3R monitoring

**For most applications, 4,400 hybrid signatures per second is more than sufficient**, and the comprehensive security architecture provides value beyond raw speed.

---

**Benchmark Script:** `benchmarks/comparative_benchmark.py`
**Generated:** 2025-11-28
**Copyright:** 2025 Steel Security Advisors LLC
**License:** Apache License 2.0
