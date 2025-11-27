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
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>

/**
 * Ava Guardian ♱ context structure (opaque)
 */
struct ava_context_t {
    ava_algorithm_t algorithm;
    void* algorithm_ctx;  /* Algorithm-specific context */
    uint32_t magic;       /* Magic number for validation */
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

    /* Algorithm-specific initialization will be done in separate modules */

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

    /* Free algorithm-specific context */
    if (ctx->algorithm_ctx) {
        /* Algorithm-specific cleanup will be done here */
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
 * Key generation (stub - will be implemented per-algorithm)
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

    /* Algorithm-specific implementation will go here */
    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Sign message (stub - will be implemented per-algorithm)
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

    /* Suppress unused parameter warnings for stub implementation */
    (void)message_len;
    (void)secret_key_len;

    /* Algorithm-specific implementation will go here */
    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Verify signature (stub - will be implemented per-algorithm)
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

    /* Suppress unused parameter warnings for stub implementation */
    (void)message_len;
    (void)signature_len;
    (void)public_key_len;

    /* Algorithm-specific implementation will go here */
    return AVA_ERROR_NOT_IMPLEMENTED;
}
