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
 * @file ava_guardian.h
 * @brief Ava Guardian ♱ (AG♱) - Core C API for Post-Quantum Cryptography
 * @version 1.0.0
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-11-24
 *
 * High-performance C implementation of quantum-resistant cryptographic primitives.
 */

#ifndef AVA_GUARDIAN_H
#define AVA_GUARDIAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * VERSION INFORMATION
 * ============================================================================ */

#define AVA_GUARDIAN_VERSION_MAJOR 1
#define AVA_GUARDIAN_VERSION_MINOR 0
#define AVA_GUARDIAN_VERSION_PATCH 0
#define AVA_GUARDIAN_VERSION_STRING "1.0.0"

/* ============================================================================
 * ALGORITHM IDENTIFIERS
 * ============================================================================ */

typedef enum {
    AVA_ALG_ML_DSA_65 = 0,    /**< CRYSTALS-Dilithium (ML-DSA-65) */
    AVA_ALG_KYBER_1024 = 1,   /**< CRYSTALS-Kyber (Kyber-1024) */
    AVA_ALG_SPHINCS_256F = 2, /**< SPHINCS+-256f */
    AVA_ALG_ED25519 = 3,      /**< Ed25519 (classical) */
    AVA_ALG_HYBRID = 4        /**< Hybrid mode (classical + PQC) */
} ava_algorithm_t;

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

typedef enum {
    AVA_SUCCESS = 0,
    AVA_ERROR_INVALID_PARAM = -1,
    AVA_ERROR_MEMORY = -2,
    AVA_ERROR_CRYPTO = -3,
    AVA_ERROR_VERIFY_FAILED = -4,
    AVA_ERROR_NOT_IMPLEMENTED = -5,
    AVA_ERROR_TIMING_ATTACK = -6,
    AVA_ERROR_SIDE_CHANNEL = -7
} ava_error_t;

/* ============================================================================
 * KEY SIZES (bytes)
 * ============================================================================ */

/* ML-DSA-65 (Dilithium3) */
#define AVA_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define AVA_ML_DSA_65_SECRET_KEY_BYTES 4016
#define AVA_ML_DSA_65_SIGNATURE_BYTES 3309

/* Kyber-1024 */
#define AVA_KYBER_1024_PUBLIC_KEY_BYTES 1568
#define AVA_KYBER_1024_SECRET_KEY_BYTES 3168
#define AVA_KYBER_1024_CIPHERTEXT_BYTES 1568
#define AVA_KYBER_1024_SHARED_SECRET_BYTES 32

/* SPHINCS+-256f */
#define AVA_SPHINCS_256F_PUBLIC_KEY_BYTES 64
#define AVA_SPHINCS_256F_SECRET_KEY_BYTES 128
#define AVA_SPHINCS_256F_SIGNATURE_BYTES 49856

/* Ed25519 */
#define AVA_ED25519_PUBLIC_KEY_BYTES 32
#define AVA_ED25519_SECRET_KEY_BYTES 64
#define AVA_ED25519_SIGNATURE_BYTES 64

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================ */

typedef struct ava_context_t ava_context_t;
typedef struct ava_keypair_t ava_keypair_t;
typedef struct ava_signature_t ava_signature_t;

/* ============================================================================
 * CONTEXT MANAGEMENT
 * ============================================================================ */

/**
 * @brief Initialize Ava Guardian context
 * @param algorithm Algorithm to use
 * @return Opaque context pointer, NULL on failure
 */
ava_context_t* ava_context_init(ava_algorithm_t algorithm);

/**
 * @brief Free Ava Guardian context and scrub memory
 * @param ctx Context to free
 */
void ava_context_free(ava_context_t* ctx);

/* ============================================================================
 * KEY GENERATION
 * ============================================================================ */

/**
 * @brief Generate a new keypair (constant-time)
 * @param ctx Initialized context
 * @param public_key Output buffer for public key
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key
 * @param secret_key_len Length of secret key buffer
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_keypair_generate(
    ava_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
);

/* ============================================================================
 * SIGNATURE OPERATIONS
 * ============================================================================ */

/**
 * @brief Sign a message (constant-time)
 * @param ctx Initialized context
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key
 * @param secret_key_len Length of secret key
 * @param signature Output buffer for signature
 * @param signature_len Pointer to signature length (in/out)
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_sign(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
);

/**
 * @brief Verify a signature (constant-time)
 * @param ctx Initialized context
 * @param message Message to verify
 * @param message_len Length of message
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param public_key Public key
 * @param public_key_len Length of public key
 * @return AVA_SUCCESS if valid, AVA_ERROR_VERIFY_FAILED if invalid
 */
ava_error_t ava_verify(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
);

/* ============================================================================
 * KEY ENCAPSULATION (Kyber-1024)
 * ============================================================================ */

/**
 * @brief Encapsulate a shared secret
 * @param ctx Initialized context (must be Kyber-1024)
 * @param public_key Recipient's public key
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_kem_encapsulate(
    ava_context_t* ctx,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/**
 * @brief Decapsulate a shared secret
 * @param ctx Initialized context (must be Kyber-1024)
 * @param ciphertext Ciphertext to decapsulate
 * @param ciphertext_len Length of ciphertext
 * @param secret_key Recipient's secret key
 * @param secret_key_len Length of secret key
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Length of shared secret buffer
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_kem_decapsulate(
    ava_context_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
);

/* ============================================================================
 * CONSTANT-TIME UTILITIES
 * ============================================================================ */

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise (timing-safe)
 */
int ava_consttime_memcmp(const void* a, const void* b, size_t len);

/**
 * @brief Secure memory scrubbing
 * @param ptr Memory to scrub
 * @param len Length to scrub
 */
void ava_secure_memzero(void* ptr, size_t len);

/**
 * @brief Constant-time conditional swap
 * @param condition Swap if non-zero
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to swap
 */
void ava_consttime_swap(int condition, void* a, void* b, size_t len);

/**
 * @brief Constant-time table lookup
 * @param table Table to lookup from
 * @param element_size Size of each element
 * @param num_elements Number of elements in table
 * @param index Index to lookup
 * @param output Output buffer for selected element
 */
void ava_consttime_lookup(
    const void* table,
    size_t element_size,
    size_t num_elements,
    size_t index,
    void* output
);

/**
 * @brief Constant-time conditional copy
 * @param condition Copy if non-zero
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length to copy
 */
void ava_consttime_copy(int condition, void* dst, const void* src, size_t len);

/* ============================================================================
 * HASHING AND KEY DERIVATION
 * ============================================================================ */

/**
 * @brief SHA3-256 hash (constant-time)
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer (32 bytes)
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_sha3_256(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief HKDF key derivation
 * @param salt Salt value
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param info Context information
 * @param info_len Length of info
 * @param okm Output key material
 * @param okm_len Desired length of OKM
 * @return AVA_SUCCESS or error code
 */
ava_error_t ava_hkdf(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
);

/* ============================================================================
 * VERSIONING
 * ============================================================================ */

/**
 * @brief Get library version string
 * @return Version string (e.g., "1.0.0")
 */
const char* ava_version_string(void);

/**
 * @brief Get library version number
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 */
void ava_version_number(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif /* AVA_GUARDIAN_H */
