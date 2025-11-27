/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ava_kyber.c
 * @brief CRYSTALS-Kyber-1024 Key Encapsulation Mechanism - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-11-24
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
 * POLYNOMIAL ARITHMETIC FOUNDATIONS
 * ============================================================================
 * These functions provide the mathematical foundations for Kyber operations.
 * poly_add, poly_sub, and montgomery_reduce are implemented.
 * NTT and other operations are placeholders for future development.
 * ============================================================================ */

static void poly_add(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = (a->coeffs[i] + b->coeffs[i]) % KYBER_Q;
    }
}

static void poly_sub(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = (a->coeffs[i] - b->coeffs[i] + KYBER_Q) % KYBER_Q;
    }
}

/**
 * Number Theoretic Transform (forward)
 *
 * PLACEHOLDER: Requires precomputed twiddle factors for Kyber's NTT.
 * Would transform polynomial to NTT domain for efficient multiplication.
 */
static void poly_ntt(poly* r) {
    /* Placeholder - full NTT requires twiddle factor tables */
    (void)r;
}

/**
 * Inverse NTT
 *
 * PLACEHOLDER: Transforms polynomial back from NTT domain.
 */
static void poly_invntt(poly* r) {
    /* Placeholder - inverse NTT implementation */
    (void)r;
}

/**
 * Pointwise multiplication in NTT domain
 *
 * PLACEHOLDER: Performs coefficient-wise multiplication with Montgomery reduction.
 */
static void poly_basemul(poly* r, const poly* a, const poly* b) {
    /* Placeholder - basemul with Montgomery reduction */
    (void)r; (void)a; (void)b;
}

/**
 * Montgomery reduction
 * Computes a * R^-1 mod q where R = 2^16
 */
static int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = (int16_t)(a * 62209);  /* q^-1 mod 2^16 */
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;

    return (int16_t)t;
}

/**
 * Compress polynomial
 *
 * PLACEHOLDER: Compresses coefficients using round(2^bits * x / q).
 * Used for ciphertext compression in Kyber.
 */
static void poly_compress(uint8_t* r, const poly* a, int bits) {
    /* Placeholder - compression for ciphertext size reduction */
    (void)r; (void)a; (void)bits;
}

/**
 * Decompress polynomial
 *
 * PLACEHOLDER: Decompresses using round(q * x / 2^bits).
 * Inverse of poly_compress for decryption.
 */
static void poly_decompress(poly* r, const uint8_t* a, int bits) {
    /* Placeholder - decompression for decryption */
    (void)r; (void)a; (void)bits;
}

/**
 * Serialize polynomial to bytes
 *
 * PLACEHOLDER: Packs 256 12-bit coefficients into 384 bytes.
 */
static void poly_tobytes(uint8_t* r, const poly* a) {
    /* Placeholder - polynomial serialization */
    (void)r; (void)a;
}

/**
 * Deserialize polynomial from bytes
 *
 * PLACEHOLDER: Unpacks 384 bytes into 256 12-bit coefficients.
 */
static void poly_frombytes(poly* r, const uint8_t* a) {
    /* Placeholder - polynomial deserialization */
    (void)r; (void)a;
}
