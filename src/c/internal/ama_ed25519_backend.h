/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_backend.h
 * @brief Entry points of the MULX+ADX instantiation of the Ed25519 group
 *        arithmetic (src/c/x86/ama_ed25519_fe64_mulx.c).
 *
 * src/c/ama_ed25519.c dispatches to these at run time when
 * ama_cpuid_has_x25519_mulx() reports BMI2 and ADX; otherwise it calls its
 * own fe51 instantiation.  One declaration, included by the definitions and
 * by the dispatcher, so the two cannot drift — the reason
 * src/c/internal/ama_x25519_fe64_mulx.h exists, applied here.
 *
 * Declared unconditionally (like ama_testing_exports.h): CMake defines
 * AMA_HAVE_ED25519_FE64_MULX_IMPL on the library targets only when the unit
 * is compiled, and the dispatcher references these names only under that
 * macro, so on every other build they are declarations of nothing and the
 * linker never looks for them.  Hidden visibility: internal to the library,
 * not ABI.
 *
 * Scalars arrive pre-recoded by the dispatcher (comb digits for the
 * constant-time base multiplication, 256 wNAF digits for the variable-time
 * ladders); points arrive and leave as compressed 32-byte encodings.  The
 * int-returning entry points return 0 on success and -1 when an encoding is
 * refused (non-canonical or not a point).
 */
#ifndef AMA_ED25519_BACKEND_H
#define AMA_ED25519_BACKEND_H

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define AMA_ED25519_BACKEND_HIDDEN __attribute__((visibility("hidden")))
#else
#define AMA_ED25519_BACKEND_HIDDEN
#endif

AMA_ED25519_BACKEND_HIDDEN
void ama_ed25519_ge_scalarmult_base_mulx(uint8_t out[32], const int8_t *comb_digits);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_verify_point_mulx(uint8_t out[32], const int8_t *wnaf_s,
                                     const int8_t *wnaf_h, const uint8_t A[32]);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_point_add_mulx(uint8_t out[32], const uint8_t p[32], const uint8_t q[32]);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_scalarmult_vartime_mulx(uint8_t out[32], const int8_t *wnaf,
                                           const uint8_t p[32]);
AMA_ED25519_BACKEND_HIDDEN
int ama_ed25519_ge_double_scalarmult_vartime_mulx(uint8_t out[32], const int8_t *w1,
                                                  const uint8_t p1[32], const int8_t *w2,
                                                  const uint8_t p2[32]);
/* Test-only (defined under AMA_TESTING_MODE in the MULX unit). */
int ama_ed25519_ge_table_entry_mulx(int which, int i, int j, uint8_t out[32]);

#endif /* AMA_ED25519_BACKEND_H */
