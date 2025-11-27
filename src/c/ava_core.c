/**
 * Copyright 2025 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ava_core.c
 * @brief Core Ava Guardian ♱ context and lifecycle management
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-11-24
 *
 * LIBOQS INTEGRATION
 * ==================
 * This file provides integration with liboqs for post-quantum cryptography.
 * When AVA_USE_LIBOQS is defined and liboqs is linked, the implementation
 * uses liboqs for ML-DSA (Dilithium) and Kyber operations.
 *
 * Build with liboqs:
 *   cmake -DAVA_USE_LIBOQS=ON ..
 *   Link against: -loqs
 *
 * Without liboqs, functions return AVA_ERROR_NOT_IMPLEMENTED.
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>

/* liboqs integration - conditionally include if available */
#ifdef AVA_USE_LIBOQS
#include <oqs/oqs.h>
#endif

/**
 * Ava Guardian ♱ context structure (opaque)
 */
struct ava_context_t {
    ava_algorithm_t algorithm;
    void* algorithm_ctx;  /* Algorithm-specific context */
    uint32_t magic;       /* Magic number for validation */
#ifdef AVA_USE_LIBOQS
    OQS_SIG* sig;         /* liboqs signature context (for Dilithium) */
    OQS_KEM* kem;         /* liboqs KEM context (for Kyber) */
#endif
};

#define AVA_CONTEXT_MAGIC 0x41564147  /* "AVAG" */

/**
 * Version information
 */
const char* ava_version_string(void) {
    return AVA_GUARDIAN_VERSION_STRING;
}

void ava_version_number(int* major, int* minor, int* patch) {
    if (major) *major = AVA_GUARDIAN_VERSION_MAJOR;
    if (minor) *minor = AVA_GUARDIAN_VERSION_MINOR;
    if (patch) *patch = AVA_GUARDIAN_VERSION_PATCH;
}

/**
 * Initialize Ava Guardian ♱ context
 */
ava_context_t* ava_context_init(ava_algorithm_t algorithm) {
    ava_context_t* ctx;

    /* Validate algorithm */
    if (algorithm < AVA_ALG_ML_DSA_65 || algorithm > AVA_ALG_HYBRID) {
        return NULL;
    }

    /* Allocate context */
    ctx = (ava_context_t*)calloc(1, sizeof(ava_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->algorithm = algorithm;
    ctx->magic = AVA_CONTEXT_MAGIC;
    ctx->algorithm_ctx = NULL;

#ifdef AVA_USE_LIBOQS
    ctx->sig = NULL;
    ctx->kem = NULL;

    /* Initialize liboqs objects based on algorithm */
    switch (algorithm) {
        case AVA_ALG_ML_DSA_65:
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_KYBER_1024:
            ctx->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
            if (!ctx->kem) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_SPHINCS_256F:
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_ED25519:
            /* Ed25519 not provided by liboqs - use separate implementation */
            break;

        case AVA_ALG_HYBRID:
            /* Hybrid mode: initialize both Dilithium and Ed25519 */
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        default:
            break;
    }
#endif

    return ctx;
}

/**
 * Free Ava Guardian ♱ context
 */
void ava_context_free(ava_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Validate magic number */
    if (ctx->magic != AVA_CONTEXT_MAGIC) {
        return;
    }

#ifdef AVA_USE_LIBOQS
    /* Free liboqs signature context */
    if (ctx->sig) {
        OQS_SIG_free(ctx->sig);
        ctx->sig = NULL;
    }

    /* Free liboqs KEM context */
    if (ctx->kem) {
        OQS_KEM_free(ctx->kem);
        ctx->kem = NULL;
    }
#endif

    /* Free algorithm-specific context */
    if (ctx->algorithm_ctx) {
        free(ctx->algorithm_ctx);
        ctx->algorithm_ctx = NULL;
    }

    /* Scrub context */
    ava_secure_memzero(ctx, sizeof(ava_context_t));

    /* Free memory */
    free(ctx);
}

/**
 * Validate context
 */
static inline int validate_context(const ava_context_t* ctx) {
    return (ctx != NULL && ctx->magic == AVA_CONTEXT_MAGIC);
}

/**
 * Get expected key sizes for algorithm
 */
static void get_key_sizes(
    ava_algorithm_t alg,
    size_t* public_key_size,
    size_t* secret_key_size,
    size_t* signature_size
) {
    switch (alg) {
        case AVA_ALG_ML_DSA_65:
            *public_key_size = AVA_ML_DSA_65_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_ML_DSA_65_SECRET_KEY_BYTES;
            *signature_size = AVA_ML_DSA_65_SIGNATURE_BYTES;
            break;

        case AVA_ALG_KYBER_1024:
            *public_key_size = AVA_KYBER_1024_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_KYBER_1024_SECRET_KEY_BYTES;
            *signature_size = 0;  /* KEM doesn't have signatures */
            break;

        case AVA_ALG_SPHINCS_256F:
            *public_key_size = AVA_SPHINCS_256F_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_SPHINCS_256F_SECRET_KEY_BYTES;
            *signature_size = AVA_SPHINCS_256F_SIGNATURE_BYTES;
            break;

        case AVA_ALG_ED25519:
            *public_key_size = AVA_ED25519_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_ED25519_SECRET_KEY_BYTES;
            *signature_size = AVA_ED25519_SIGNATURE_BYTES;
            break;

        default:
            *public_key_size = 0;
            *secret_key_size = 0;
            *signature_size = 0;
            break;
    }
}

/**
 * Key generation using liboqs
 */
ava_error_t ava_keypair_generate(
    ava_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    size_t expected_pk_size, expected_sk_size, sig_size;

    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!public_key || !secret_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Check sizes */
    get_key_sizes(ctx->algorithm, &expected_pk_size, &expected_sk_size, &sig_size);

    if (public_key_len < expected_pk_size || secret_key_len < expected_sk_size) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    /* Handle signature algorithms */
    if (ctx->sig) {
        rc = OQS_SIG_keypair(ctx->sig, public_key, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* Handle KEM algorithms */
    if (ctx->kem) {
        rc = OQS_KEM_keypair(ctx->kem, public_key, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Sign message using liboqs
 */
ava_error_t ava_sign(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!message || !secret_key || !signature || !signature_len) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->sig) {
        /* Validate secret key length */
        if (secret_key_len < ctx->sig->length_secret_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate signature buffer size */
        if (*signature_len < ctx->sig->length_signature) {
            *signature_len = ctx->sig->length_signature;
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Sign the message */
        rc = OQS_SIG_sign(ctx->sig, signature, signature_len,
                         message, message_len, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* KEM doesn't support signing */
    if (ctx->kem) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        (void)secret_key_len;
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#else
    /* Suppress unused parameter warnings when liboqs not available */
    (void)message_len;
    (void)secret_key_len;
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Verify signature using liboqs
 */
ava_error_t ava_verify(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!message || !signature || !public_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->sig) {
        /* Validate public key length */
        if (public_key_len < ctx->sig->length_public_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Verify the signature */
        rc = OQS_SIG_verify(ctx->sig, message, message_len,
                           signature, signature_len, public_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_VERIFY_FAILED;
        }
        return AVA_SUCCESS;
    }

    /* KEM doesn't support verification */
    if (ctx->kem) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        (void)message_len;
        (void)signature_len;
        (void)public_key_len;
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#else
    /* Suppress unused parameter warnings when liboqs not available */
    (void)message_len;
    (void)signature_len;
    (void)public_key_len;
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}
