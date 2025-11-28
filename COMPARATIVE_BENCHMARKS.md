# Comparative Performance Benchmarks

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.0.0 |
| Test Date | 2025-11-28 |
| Classification | Public |
| Maintainer | Steel Security Advisors LLC |

---

## Executive Summary

This document contains comparative performance benchmarks between **Ava Guardian ♱** and other cryptographic implementations for Ed25519 signature operations.

### Implementations Tested

1. **Ava Guardian ♱** - Hybrid Python/Cython implementation
2. **cryptography library** - OpenSSL-backed implementation (de facto standard)
3. **liboqs-python** - Not available (requires system liboqs C library installation)

### Key Findings

**Ed25519 Signing:**
- cryptography (OpenSSL): **21,187 ops/sec** (0.0472ms)
- Ava Guardian: **10,219 ops/sec** (0.0979ms)
- **Result:** OpenSSL is **2.07x faster** for Ed25519 signing

**Ed25519 Verification:**
- cryptography (OpenSSL): **8,298 ops/sec** (0.1205ms)
- Ava Guardian: **8,289 ops/sec** (0.1206ms)
- **Result:** **Essentially identical performance** (0.11% difference)

---

## Detailed Results

### Test Environment

```
OS: Linux 4.4.0 x86_64
CPU: 16 cores
Memory: 13.0 GB
Python: 3.11
Iterations: 1,000 per operation
```

### Ed25519 Sign Performance

| Implementation | Mean Time (ms) | Throughput (ops/sec) | Relative Performance |
|----------------|----------------|----------------------|----------------------|
| cryptography (OpenSSL) | 0.0472 | **21,187** | Baseline (fastest) |
| Ava Guardian | 0.0979 | 10,219 | 2.07x slower |

**Analysis:**
- OpenSSL's Ed25519 implementation is highly optimized C code
- Ava Guardian's Python/Cython layer adds overhead
- For pure Ed25519 operations, OpenSSL backend is significantly faster

### Ed25519 Verify Performance

| Implementation | Mean Time (ms) | Throughput (ops/sec) | Relative Performance |
|----------------|----------------|----------------------|----------------------|
| cryptography (OpenSSL) | 0.1205 | 8,298 | Baseline |
| Ava Guardian | 0.1206 | 8,289 | 0.11% slower (negligible) |

**Analysis:**
- Verification performance is essentially identical
- Both implementations likely use similar verification algorithms
- Python overhead is minimal for verification path

---

## Interpretation

### What These Results Mean

1. **Classical Operations**: For pure Ed25519 operations, OpenSSL-backed implementations are faster
2. **Verification Parity**: Ava Guardian achieves comparable verification performance
3. **Signing Overhead**: ~2x slowdown for signing is attributable to Python/Cython layer overhead

### What These Results DON'T Show

⚠️ **Important Limitations:**

1. **No Hybrid Comparison**: Could not test hybrid Ed25519 + ML-DSA-65 due to liboqs unavailability
2. **No Full Package Comparison**: Did not test full 6-layer package creation (Ava Guardian's differentiator)
3. **No PQC Comparison**: Unable to benchmark ML-DSA-65 (Dilithium) performance comparatively
4. **No 3R Overhead Comparison**: Did not measure Ava Guardian's 3R monitoring impact vs competitors

### Ava Guardian's Actual Value Proposition

These benchmarks compare **isolated classical Ed25519 operations only**. Ava Guardian's value is in:

1. **6-Layer Defense-in-Depth**: SHA3-256 + HMAC + Ed25519 + ML-DSA-65 + HKDF + RFC 3161
2. **3R Security Monitoring**: Runtime anomaly detection (<2% overhead)
3. **Hybrid Signatures**: Combined classical + quantum-resistant protection
4. **Integrated System**: Full package with key management, ethical constraints, etc.

**Fair Comparison Would Require:**
- Hybrid signature benchmarks (Ed25519 + ML-DSA-65 combined)
- Full package creation with all 6 layers
- Including 3R monitoring overhead
- Against other hybrid PQC implementations (not just classical OpenSSL)

---

## Conclusion

### Honest Assessment

**For pure Ed25519 operations:**
- ✅ OpenSSL is faster for signing (~2x)
- ✅ Performance is equivalent for verification

**Ava Guardian is NOT the fastest for classical-only Ed25519 operations.**

**Where Ava Guardian Excels:**
- 6-layer defense-in-depth architecture
- Hybrid classical + quantum-resistant signatures
- 3R runtime security monitoring
- Integrated key management and ethical constraints

### Recommendations

1. **Use OpenSSL/cryptography** for:
   - Pure Ed25519 operations
   - Maximum classical performance
   - No PQC requirements

2. **Use Ava Guardian** for:
   - Hybrid classical + quantum-resistant protection
   - Defense-in-depth security architecture
   - Runtime security monitoring
   - Long-term data protection (50+ years)

---

## Raw Data

Complete benchmark results available in: `benchmarks/comparative_benchmark_results.json`

**Comparison Metrics:**
```json
{
  "Ed25519 Sign": {
    "slowdown_factor": 0.4823,
    "ava_guardian_faster_by_percent": -51.77
  },
  "Ed25519 Verify": {
    "slowdown_factor": 0.9989,
    "ava_guardian_faster_by_percent": -0.11
  }
}
```

*Negative percentages indicate Ava Guardian is slower.*

---

## Future Work

To properly compare hybrid PQC implementations, we need:

1. ✅ Install liboqs C library system-wide
2. ✅ Benchmark hybrid Ed25519 + ML-DSA-65 operations
3. ✅ Compare against other hybrid implementations (e.g., OQS-OpenSSL)
4. ✅ Measure full 6-layer package creation end-to-end
5. ✅ Include 3R monitoring overhead in comparisons

---

**Benchmark Script:** `benchmarks/comparative_benchmark.py`
**Generated:** 2025-11-28
**Copyright:** 2025 Steel Security Advisors LLC
**License:** Apache License 2.0
