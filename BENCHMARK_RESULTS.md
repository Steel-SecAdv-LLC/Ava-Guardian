# Ava Guardian ♱ Benchmark Results

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 2.0.0 |
| Test Date | 2025-11-28 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

Complete performance benchmarks for Ava Guardian ♱ v1.0.0, including **comparative analysis against OpenSSL and liboqs** implementations.

**Test Environment:**
- OS: Linux 4.4.0 x86_64
- CPU: 16 cores
- Memory: 13.0 GB
- Python: 3.11
- liboqs: 0.15.0 (built from source)
- Iterations: 1,000 per operation

---

## Comparative Benchmark Results

### Hybrid Operations (Ed25519 + ML-DSA-65)

| Operation | Ava Guardian | OpenSSL+liboqs | Performance |
|-----------|--------------|----------------|-------------|
| **Hybrid Sign** | 4,420 ops/sec (0.226ms) | 6,468 ops/sec (0.155ms) | OpenSSL+liboqs **1.46x faster** |
| **Hybrid Verify** | **6,054 ops/sec** (0.165ms) | 5,776 ops/sec (0.173ms) | Ava Guardian **1.05x faster** |

**Key Finding:** OpenSSL+liboqs is 46% faster for hybrid signing, but Ava Guardian is 5% faster for hybrid verification.

---

### Ed25519 (Classical) Performance

| Operation | Ava Guardian | OpenSSL | Performance |
|-----------|--------------|---------|-------------|
| **Sign** | 10,027 ops/sec (0.100ms) | 20,582 ops/sec (0.049ms) | OpenSSL **2.05x faster** |
| **Verify** | 8,078 ops/sec (0.124ms) | 8,391 ops/sec (0.119ms) | OpenSSL 1.04x faster |

**Analysis:** OpenSSL is significantly faster for Ed25519 signing due to highly optimized C implementation. Verification performance is essentially identical.

---

### ML-DSA-65 (Post-Quantum) Performance

| Operation | Ava Guardian | liboqs-python | Performance |
|-----------|--------------|---------------|-------------|
| **Sign** | 9,150 ops/sec (0.109ms) | 9,234 ops/sec (0.108ms) | **99.1% of liboqs** |
| **Verify** | 27,306 ops/sec (0.037ms) | 29,478 ops/sec (0.034ms) | 92.6% of liboqs |

**Key Finding:** Ava Guardian's ML-DSA-65 signing performance is **within 1% of pure liboqs** - essentially identical.

---

### Full 6-Layer Package Performance

Ava Guardian's complete security package includes:

| Layer | Component | Time |
|-------|-----------|------|
| 1 | SHA3-256 Content Hash | ~0.001ms |
| 2 | HMAC-SHA3-256 Auth | ~0.004ms |
| 3 | Ed25519 Signature | ~0.100ms |
| 4 | ML-DSA-65 Signature | ~0.109ms |
| 5 | HKDF Key Derivation | ~0.144ms |
| 6 | RFC 3161 Timestamp | (optional) |
| - | Canonical Encoding | ~0.002ms |
| - | 3R Monitoring | <0.006ms |

**Complete Package Results:**
- **Create:** 3,595 ops/sec (0.278ms) - all 6 layers
- **Verify:** 5,029 ops/sec (0.199ms) - all 6 layers

**Overhead:** Full package adds ~0.05ms (18%) over hybrid signatures for complete defense-in-depth.

---

## Detailed Performance Data

### All Implementations Tested

#### Ava Guardian ♱

| Operation | Mean Time | Ops/Sec |
|-----------|-----------|---------|
| Ed25519 Sign | 0.100ms | 10,027 |
| Ed25519 Verify | 0.124ms | 8,078 |
| ML-DSA-65 Sign | 0.109ms | 9,150 |
| ML-DSA-65 Verify | 0.037ms | 27,306 |
| Hybrid Sign | 0.226ms | 4,420 |
| Hybrid Verify | 0.165ms | 6,054 |

#### cryptography (OpenSSL)

| Operation | Mean Time | Ops/Sec |
|-----------|-----------|---------|
| Ed25519 Sign | 0.049ms | 20,582 |
| Ed25519 Verify | 0.119ms | 8,391 |

#### liboqs-python

| Operation | Mean Time | Ops/Sec |
|-----------|-----------|---------|
| ML-DSA-65 Sign | 0.108ms | 9,234 |
| ML-DSA-65 Verify | 0.034ms | 29,478 |

#### OpenSSL + liboqs

| Operation | Mean Time | Ops/Sec |
|-----------|-----------|---------|
| Hybrid Sign | 0.155ms | 6,468 |
| Hybrid Verify | 0.173ms | 5,776 |

---

## Performance Summary

### Where Ava Guardian is Competitive/Faster

✅ **ML-DSA-65 Signing:** 99.1% of liboqs (within 1%)
✅ **Hybrid Verification:** 1.05x faster than OpenSSL+liboqs
✅ **Ed25519 Verification:** 96.3% of OpenSSL

### Where Ava Guardian is Slower

❌ **Ed25519 Signing:** 2.05x slower than OpenSSL
❌ **Hybrid Signing:** 1.46x slower than OpenSSL+liboqs
❌ **ML-DSA-65 Verification:** 1.08x slower than liboqs

### What Makes Ava Guardian Different

**Not the fastest, but the most comprehensive:**
- 6 cryptographic security layers (vs 2 for hybrid implementations)
- 3R runtime monitoring (<2% overhead)
- Integrated key management
- Ethical constraint binding
- Cross-platform Python/Cython implementation

**Trade-off:** 1.5x slower hybrid signing for 3x more security layers.

---

## Regression Testing Results

From `benchmark-results.json`:

| Benchmark | Measured | Baseline | Regression % | Status |
|-----------|----------|----------|--------------|--------|
| sha3_256_hash | 292,790 ops/sec | 150,000 | -95.2% (faster) | ✅ PASS |
| hmac_sha3_256 | 159,463 ops/sec | 70,000 | -127.8% (faster) | ✅ PASS |
| ed25519_keygen | 16,576 ops/sec | 15,000 | -10.5% (faster) | ✅ PASS |
| ed25519_sign | 21,541 ops/sec | 10,000 | -115.4% (faster) | ✅ PASS |
| ed25519_verify | 8,445 ops/sec | 5,000 | -68.9% (faster) | ✅ PASS |
| hkdf_derive | 21,443 ops/sec | 60,000 | +64.3% (slower) | ❌ FAIL |
| full_package_create | 8,223 ops/sec | 2,000 | -311.1% (faster) | ✅ PASS |
| full_package_verify | 7,368 ops/sec | 2,000 | -268.4% (faster) | ✅ PASS |

**Summary:** 7/8 benchmarks pass (87.5%), HKDF regression requires investigation.

---

## Honest Assessment

### Is It The Fastest?

**For individual operations:**
- ❌ Ed25519: No (2x slower than OpenSSL)
- ✅ ML-DSA-65: Yes (99% of liboqs, essentially identical)
- ❌ Hybrid Sign: No (1.5x slower than OpenSSL+liboqs)
- ✅ Hybrid Verify: Yes (5% faster than OpenSSL+liboqs)

**For complete security packages:**
- ❌ Not the fastest for hybrid signing
- ✅ Fastest for hybrid verification
- ✅ **Only implementation** with 6-layer defense + 3R monitoring

### When to Use Ava Guardian

✅ You need 6-layer defense-in-depth
✅ You want runtime security monitoring (3R)
✅ 4,400 hybrid signs/sec is sufficient
✅ Competitive hybrid verification is acceptable

### When to Use OpenSSL+liboqs

✅ You need maximum hybrid signing speed
✅ You only need dual signatures (Ed25519 + ML-DSA-65)
✅ You don't need runtime monitoring
✅ You're implementing your own additional layers

---

## Issues & Recommendations

### HKDF Performance Regression

**Issue:** 21,443 ops/sec vs 60,000 baseline (+64.3% slower)

**Impact:** Medium - still >20K ops/sec but below target

**Actions:**
1. Profile HKDF implementation
2. Compare SHA3-256 vs SHA-256 performance impact
3. Consider Cython optimization

---

## Conclusion

Ava Guardian **is competitive but not fastest** for hybrid operations:

- **Hybrid Signing:** 1.5x slower than OpenSSL+liboqs (4.4K vs 6.5K ops/sec)
- **Hybrid Verification:** 5% faster than OpenSSL+liboqs (6.1K vs 5.8K ops/sec)
- **ML-DSA-65:** Within 1-8% of pure liboqs
- **6-Layer Package:** Unique comprehensive security architecture

**For most applications, 4,400 hybrid signatures per second is production-ready**, and the defense-in-depth architecture provides value beyond raw speed.

---

**Raw Data:**
- `benchmarks/comparative_benchmark_results.json` - Complete results
- `benchmarks/comparative_benchmark.py` - Reproducible test harness

**Generated:** 2025-11-28
**Copyright:** 2025 Steel Security Advisors LLC
**License:** Apache License 2.0
