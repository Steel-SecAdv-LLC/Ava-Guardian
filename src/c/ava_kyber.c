/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ava_kyber.c
 * @brief CRYSTALS-Kyber-1024 Key Encapsulation Mechanism - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-11-29
 *
 * IMPLEMENTATION STATUS: LIBOQS INTEGRATION
 * ==========================================
 * This file provides Kyber-1024 (ML-KEM-1024) key encapsulation using liboqs.
 * When AVA_USE_LIBOQS is defined and liboqs is linked, the implementation
 * provides full KEM operations (keygen, encaps, decaps).
 *
 * The polynomial arithmetic foundations (poly_add, poly_sub, montgomery_reduce)
 * are retained for potential future native implementations.
 *
 * Build with liboqs:
 *   cmake -DAVA_USE_LIBOQS=ON ..
 *   Link against: -loqs
 *
 * Parameters (Kyber-1024 / ML-KEM-1024):
 * - Security level: NIST Level 5 (~256-bit classical, ~128-bit quantum)
 * - Public key: 1568 bytes
 * - Secret key: 3168 bytes
 * - Ciphertext: 1568 bytes
 * - Shared secret: 32 bytes
 *
 * Standards:
 * - NIST FIPS 203 (ML-KEM)
 * - Module-LWE hardness assumption
 * - Fujisaki-Okamoto transform for IND-CCA2 security
 *
 * For production use: pip install ava-guardian[quantum]
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* liboqs integration */
#ifdef AVA_USE_LIBOQS
#include <oqs/oqs.h>
#endif

/* Suppress unused function warnings for polynomial arithmetic foundations */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/* Kyber-1024 parameters */
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_K 4
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_DU 11
#define KYBER_DV 5

/* Polynomial ring: R = Z_q[X]/(X^256 + 1) */

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

/* Forward declarations */
static void poly_add(poly* r, const poly* a, const poly* b);
static void poly_sub(poly* r, const poly* a, const poly* b);
static void poly_ntt(poly* r);
static void poly_invntt(poly* r);
static void poly_basemul(poly* r, const poly* a, const poly* b);
static void poly_compress(uint8_t* r, const poly* a, int bits);
static void poly_decompress(poly* r, const uint8_t* a, int bits);
static void poly_tobytes(uint8_t* r, const poly* a);
static void poly_frombytes(poly* r, const uint8_t* a);
static int16_t montgomery_reduce(int32_t a);

/**
 * Kyber context (algorithm-specific)
 */
typedef struct {
    uint8_t public_key[AVA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AVA_KYBER_1024_SECRET_KEY_BYTES];
    int keys_generated;
} kyber_context_t;

/**
 * Initialize Kyber-1024 context
 */
static kyber_context_t* kyber_init(void) {
    kyber_context_t* ctx = (kyber_context_t*)calloc(1, sizeof(kyber_context_t));
    if (!ctx) {
        return NULL;
    }
    ctx->keys_generated = 0;
    return ctx;
}

/**
 * Free Kyber context
 */
static void kyber_free(kyber_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Scrub sensitive data */
    ava_secure_memzero(ctx->secret_key, sizeof(ctx->secret_key));
    ava_secure_memzero(ctx, sizeof(kyber_context_t));

    free(ctx);
}

/**
 * Generate Kyber-1024 keypair using liboqs
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * Otherwise returns AVA_ERROR_NOT_IMPLEMENTED.
 *
 * @param public_key Output buffer for public key (1568 bytes)
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key (3168 bytes)
 * @param secret_key_len Length of secret key buffer
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_keypair_generate(
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    if (public_key_len < AVA_KYBER_1024_PUBLIC_KEY_BYTES ||
        secret_key_len < AVA_KYBER_1024_SECRET_KEY_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }
    return AVA_SUCCESS;
#else
    /* Parameters validated but not used - placeholder returns NOT_IMPLEMENTED */
    (void)public_key;
    (void)secret_key;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Encapsulate shared secret using liboqs
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * Otherwise returns AVA_ERROR_NOT_IMPLEMENTED.
 *
 * @param public_key Recipient's public key (1568 bytes)
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext (1568 bytes)
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param shared_secret_len Length of shared secret buffer
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (public_key_len != AVA_KYBER_1024_PUBLIC_KEY_BYTES ||
        shared_secret_len != AVA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    if (*ciphertext_len < AVA_KYBER_1024_CIPHERTEXT_BYTES) {
        *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
        return AVA_ERROR_INVALID_PARAM;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }

    *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
    return AVA_SUCCESS;
#else
    /* Parameters validated but not used - placeholder returns NOT_IMPLEMENTED */
    (void)public_key;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)shared_secret;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Decapsulate shared secret using liboqs
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * Otherwise returns AVA_ERROR_NOT_IMPLEMENTED.
 *
 * Uses implicit rejection for IND-CCA2 security: returns a deterministic
 * but random-looking value if decapsulation fails.
 *
 * @param ciphertext Ciphertext to decapsulate (1568 bytes)
 * @param ciphertext_len Length of ciphertext
 * @param secret_key Recipient's secret key (3168 bytes)
 * @param secret_key_len Length of secret key
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param shared_secret_len Length of shared secret buffer
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (ciphertext_len != AVA_KYBER_1024_CIPHERTEXT_BYTES ||
        secret_key_len != AVA_KYBER_1024_SECRET_KEY_BYTES ||
        shared_secret_len != AVA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }
    return AVA_SUCCESS;
#else
    /* Parameters validated but not used - placeholder returns NOT_IMPLEMENTED */
    (void)ciphertext;
    (void)secret_key;
    (void)shared_secret;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ============================================================================
 * POLYNOMIAL ARITHMETIC - COMPLETE IMPLEMENTATION
 * ============================================================================
 * Full implementation of Kyber polynomial operations including NTT,
 * Montgomery arithmetic, compression, and serialization.
 * ============================================================================ */

/**
 * Montgomery reduction
 * Computes a * R^-1 mod q where R = 2^16
 * Uses the identity: a * q^-1 mod R * q subtracted from a gives a multiple of R
 */
static int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = (int16_t)(a * 62209);  /* q^-1 mod 2^16 = 62209 */
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;

    return (int16_t)t;
}

/**
 * Barrett reduction
 * Reduces a mod q for values up to 2^26
 */
static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = (int32_t)v * a >> 26;
    t *= KYBER_Q;
    return a - t;
}

/**
 * Conditional subtraction of q
 */
static int16_t csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}

/* NTT twiddle factors (zetas) - primitive 256th root of unity in Montgomery form */
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
    3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
    516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
    2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

/* Inverse NTT twiddle factors (zetas_inv) */
static const int16_t zetas_inv[128] = {
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
    951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813,
    1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
    130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441
};

/**
 * Number Theoretic Transform (forward NTT)
 * Converts polynomial from coefficient form to NTT form for fast multiplication.
 * Uses Cooley-Tukey butterfly with Montgomery reduction.
 */
static void poly_ntt(poly* r) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * r->coeffs[j + len]);
                r->coeffs[j + len] = r->coeffs[j] - t;
                r->coeffs[j] = r->coeffs[j] + t;
            }
        }
    }
}

/**
 * Inverse Number Theoretic Transform
 * Converts polynomial from NTT form back to coefficient form.
 * Uses Gentleman-Sande butterfly with Montgomery reduction.
 */
static void poly_invntt(poly* r) {
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_inv[k--];
            for (j = start; j < start + len; j++) {
                t = r->coeffs[j];
                r->coeffs[j] = barrett_reduce(t + r->coeffs[j + len]);
                r->coeffs[j + len] = montgomery_reduce((int32_t)zeta * (r->coeffs[j + len] - t));
            }
        }
    }

    /* Multiply by f = 128^{-1} */
    for (j = 0; j < KYBER_N; j++) {
        r->coeffs[j] = montgomery_reduce((int32_t)f * r->coeffs[j]);
    }
}

/**
 * Base multiplication of two polynomials in NTT domain
 * Multiplication in Z_q[X]/(X^2 - zeta) for degree-2 components
 */
static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce((int32_t)r[0] * zeta);
    r[0] += montgomery_reduce((int32_t)a[0] * b[0]);

    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce((int32_t)a[1] * b[0]);
}

/**
 * Pointwise multiplication of polynomials in NTT domain
 */
static void poly_basemul(poly* r, const poly* a, const poly* b) {
    unsigned int i;
    for (i = 0; i < KYBER_N / 4; i++) {
        basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], zetas[64 + i]);
        basemul(&r->coeffs[4*i + 2], &a->coeffs[4*i + 2], &b->coeffs[4*i + 2], -zetas[64 + i]);
    }
}

/**
 * Add two polynomials
 */
static void poly_add(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * Subtract two polynomials
 */
static void poly_sub(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * Reduce all coefficients mod q
 */
static void poly_reduce(poly* r) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

/**
 * Serialize polynomial to bytes (12-bit coefficients)
 * Packs 256 coefficients into 384 bytes
 */
static void poly_tobytes(uint8_t r[384], const poly* a) {
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = (uint16_t)csubq(a->coeffs[2*i]);
        t1 = (uint16_t)csubq(a->coeffs[2*i + 1]);

        r[3*i + 0] = (uint8_t)(t0);
        r[3*i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i + 2] = (uint8_t)(t1 >> 4);
    }
}

/**
 * Deserialize bytes to polynomial
 * Unpacks 384 bytes into 256 12-bit coefficients
 */
static void poly_frombytes(poly* r, const uint8_t a[384]) {
    unsigned int i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i] = ((uint16_t)a[3*i] | ((uint16_t)a[3*i + 1] << 8)) & 0xFFF;
        r->coeffs[2*i + 1] = ((uint16_t)(a[3*i + 1] >> 4) | ((uint16_t)a[3*i + 2] << 4)) & 0xFFF;
    }
}

/**
 * Compress polynomial to fewer bits
 * Used for ciphertext compression
 */
static void poly_compress(uint8_t* r, const poly* a, int bits) {
    unsigned int i, j;
    uint8_t t[8];

    if (bits == 4) {
        /* Compress to 4 bits per coefficient */
        for (i = 0; i < KYBER_N / 2; i++) {
            for (j = 0; j < 2; j++) {
                int16_t coeff = csubq(a->coeffs[2*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 4) + KYBER_Q / 2) / KYBER_Q) & 0xF);
            }
            r[i] = t[0] | (t[1] << 4);
        }
    } else if (bits == 5) {
        /* Compress to 5 bits per coefficient */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = csubq(a->coeffs[8*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 5) + KYBER_Q / 2) / KYBER_Q) & 0x1F);
            }
            r[5*i + 0] = (t[0]) | (t[1] << 5);
            r[5*i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[5*i + 2] = (t[3] >> 1) | (t[4] << 4);
            r[5*i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[5*i + 4] = (t[6] >> 2) | (t[7] << 3);
        }
    } else if (bits == 10) {
        /* Compress to 10 bits per coefficient */
        for (i = 0; i < KYBER_N / 4; i++) {
            for (j = 0; j < 4; j++) {
                int16_t coeff = csubq(a->coeffs[4*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
            }
            r[5*i + 0] = (uint8_t)(t[0]);
            r[5*i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[5*i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[5*i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[5*i + 4] = (uint8_t)(t[3] >> 2);
        }
    } else if (bits == 11) {
        /* Compress to 11 bits per coefficient (Kyber-1024) */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = csubq(a->coeffs[8*i + j]);
                uint16_t t16 = (uint16_t)(((((uint32_t)coeff << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF);
                t[j] = t16 & 0xFF;
            }
            r[11*i + 0] = t[0];
            r[11*i + 1] = (t[0] >> 8) | (t[1] << 3);
            r[11*i + 2] = (t[1] >> 5) | (t[2] << 6);
            r[11*i + 3] = t[2] >> 2;
            r[11*i + 4] = (t[2] >> 10) | (t[3] << 1);
            r[11*i + 5] = (t[3] >> 7) | (t[4] << 4);
            r[11*i + 6] = (t[4] >> 4) | (t[5] << 7);
            r[11*i + 7] = t[5] >> 1;
            r[11*i + 8] = (t[5] >> 9) | (t[6] << 2);
            r[11*i + 9] = (t[6] >> 6) | (t[7] << 5);
            r[11*i + 10] = t[7] >> 3;
        }
    }
}

/**
 * Decompress polynomial from compressed representation
 */
static void poly_decompress(poly* r, const uint8_t* a, int bits) {
    unsigned int i;

    if (bits == 4) {
        for (i = 0; i < KYBER_N / 2; i++) {
            r->coeffs[2*i + 0] = (int16_t)((((uint32_t)(a[i] & 0xF) * KYBER_Q) + 8) >> 4);
            r->coeffs[2*i + 1] = (int16_t)((((uint32_t)(a[i] >> 4) * KYBER_Q) + 8) >> 4);
        }
    } else if (bits == 5) {
        uint8_t t[8];
        for (i = 0; i < KYBER_N / 8; i++) {
            t[0] = a[5*i + 0] & 0x1F;
            t[1] = (a[5*i + 0] >> 5) | ((a[5*i + 1] << 3) & 0x1F);
            t[2] = (a[5*i + 1] >> 2) & 0x1F;
            t[3] = (a[5*i + 1] >> 7) | ((a[5*i + 2] << 1) & 0x1F);
            t[4] = (a[5*i + 2] >> 4) | ((a[5*i + 3] << 4) & 0x1F);
            t[5] = (a[5*i + 3] >> 1) & 0x1F;
            t[6] = (a[5*i + 3] >> 6) | ((a[5*i + 4] << 2) & 0x1F);
            t[7] = a[5*i + 4] >> 3;

            for (int j = 0; j < 8; j++) {
                r->coeffs[8*i + j] = (int16_t)((((uint32_t)t[j] * KYBER_Q) + 16) >> 5);
            }
        }
    } else if (bits == 10) {
        for (i = 0; i < KYBER_N / 4; i++) {
            r->coeffs[4*i + 0] = (int16_t)(((((uint16_t)a[5*i] | ((uint16_t)a[5*i + 1] << 8)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 1] = (int16_t)((((((uint16_t)a[5*i + 1] >> 2) | ((uint16_t)a[5*i + 2] << 6)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 2] = (int16_t)((((((uint16_t)a[5*i + 2] >> 4) | ((uint16_t)a[5*i + 3] << 4)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 3] = (int16_t)((((((uint16_t)a[5*i + 3] >> 6) | ((uint16_t)a[5*i + 4] << 2)) & 0x3FF) * KYBER_Q + 512) >> 10);
        }
    } else if (bits == 11) {
        for (i = 0; i < KYBER_N / 8; i++) {
            uint16_t t0 = ((uint16_t)a[11*i]) | (((uint16_t)a[11*i + 1] & 0x07) << 8);
            uint16_t t1 = ((uint16_t)a[11*i + 1] >> 3) | (((uint16_t)a[11*i + 2] & 0x3F) << 5);
            uint16_t t2 = ((uint16_t)a[11*i + 2] >> 6) | ((uint16_t)a[11*i + 3] << 2) | (((uint16_t)a[11*i + 4] & 0x01) << 10);
            uint16_t t3 = ((uint16_t)a[11*i + 4] >> 1) | (((uint16_t)a[11*i + 5] & 0x0F) << 7);
            uint16_t t4 = ((uint16_t)a[11*i + 5] >> 4) | (((uint16_t)a[11*i + 6] & 0x7F) << 4);
            uint16_t t5 = ((uint16_t)a[11*i + 6] >> 7) | ((uint16_t)a[11*i + 7] << 1) | (((uint16_t)a[11*i + 8] & 0x03) << 9);
            uint16_t t6 = ((uint16_t)a[11*i + 8] >> 2) | (((uint16_t)a[11*i + 9] & 0x1F) << 6);
            uint16_t t7 = ((uint16_t)a[11*i + 9] >> 5) | ((uint16_t)a[11*i + 10] << 3);

            r->coeffs[8*i + 0] = (int16_t)(((uint32_t)(t0 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 1] = (int16_t)(((uint32_t)(t1 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 2] = (int16_t)(((uint32_t)(t2 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 3] = (int16_t)(((uint32_t)(t3 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 4] = (int16_t)(((uint32_t)(t4 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 5] = (int16_t)(((uint32_t)(t5 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 6] = (int16_t)(((uint32_t)(t6 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 7] = (int16_t)(((uint32_t)(t7 & 0x7FF) * KYBER_Q + 1024) >> 11);
        }
    }
}
