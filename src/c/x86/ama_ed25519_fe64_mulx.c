/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_fe64_mulx.c
 * @brief Ed25519 group arithmetic over the radix-2^64 field with the
 *        MULX+ADX multiply and square kernel (x86-64 GCC/Clang only).
 *
 * The second instantiation of src/c/internal/ama_ed25519_ge.h.  Every group
 * formula, table walk and constant-time selection is the same source text
 * the fe51 instantiation in src/c/ama_ed25519.c compiles; only the field
 * layer differs:
 *
 *   multiply / square   internal/ama_fe64_mulx_kernel.h — the fused MULX /
 *                       ADCX / ADOX blocks X25519 already ships, inlined
 *   add / sub / neg     src/c/fe64.h, 4-limb with the 2^256 = 38 fold
 *   encode / decode     fe64_frombytes / fe64_tobytes
 *   tables              ama_ed25519_tables.h in its radix-2^64 rendering
 *
 * Compiled per-file with -mbmi2 -madx (CMakeLists.txt, AMA_ED25519_MULX_
 * SOURCES), so the compiler may also emit BMI2 shifts in the plain C here;
 * that is why src/c/ama_ed25519.c calls into this unit only when
 * ama_cpuid_has_x25519_mulx() has reported BMI2 and ADX, and why every
 * function this unit defines — the entry points below and each static
 * function the template instantiates — carries the `_mulx` suffix
 * tools/check_avx_scoping.py requires of symbols that contain BMI2/ADX
 * instructions.
 *
 * Field-operation counts per group operation on this path (M = multiply,
 * S = square, A = add/sub/neg on 4 limbs), for the ledger:
 *   mixed add p3 + niels -> p3        3M + 4M (p1p1 -> p3)   = 7M, 6A
 *   mixed add p3 + pniels -> p3       4M + 4M                = 8M, 6A
 *   doubling p2 -> p1p1               4S,                      5A
 *   doubling to the next p2 / p3      4S + 3M / 4S + 4M
 *   constant-time select (8 entries)  0M, 1 neg + masked merges
 *
 * Outputs are byte-identical to the fe51 instantiation:
 * tests/c/test_ed25519_fe51_mulx_equiv.c drives both through the public
 * API on every x86-64 host that has BMI2 and ADX, and the frozen oracle and
 * RFC 8032 vectors are replayed against whichever instantiation the
 * dispatcher selects.
 */

#if (defined(__x86_64__) || defined(_M_X64)) \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_MSC_VER)

#include "../../../include/ama_cryptography.h"
#include "../internal/ama_ed25519_backend.h"
#include "../fe64.h"
#include "../internal/ama_fe64_mulx_kernel.h"

#define AMA_ED25519_TABLES_FE64
#include "../internal/ama_ed25519_tables.h"

/* The mulx kernels take uint64_t[4]; fe64 is uint64_t[4]. */
static inline __attribute__((always_inline))
void ed25519_fe64_mul_mulx(fe64 h, const fe64 f, const fe64 g) {
    ama_fe64_mul_mulx_inline(h, f, g);
}
static inline __attribute__((always_inline))
void ed25519_fe64_sq_mulx(fe64 h, const fe64 f) {
    ama_fe64_sq_mulx_inline(h, f);
}

#define GE_SUFFIX mulx
#define GE_LINKAGE AMA_ED25519_BACKEND_HIDDEN
#define GE_FE fe64
#define GE_FE_LIMBS 4
#define GE_FE_0(h) fe64_0(h)
#define GE_FE_1(h) fe64_1(h)
#define GE_FE_COPY(h, f) fe64_copy(h, f)
#define GE_FE_ADD(h, f, g) fe64_add(h, f, g)
#define GE_FE_SUB(h, f, g) fe64_sub(h, f, g)
#define GE_FE_SUB_M(h, f, g) fe64_sub(h, f, g)   /* exact: radix 2^64 has no headroom */
#define GE_FE_SUB_S(h, f, g) fe64_sub(h, f, g)
#define GE_FE_NEG(h, f) fe64_neg(h, f)
#define GE_FE_MUL(h, f, g) ed25519_fe64_mul_mulx(h, f, g)
#define GE_FE_SQ(h, f) ed25519_fe64_sq_mulx(h, f)
#define GE_FE_FROMBYTES(h, s) fe64_frombytes(h, s)
#define GE_FE_TOBYTES(s, h) fe64_tobytes(s, h)
#define GE_NIELS ama_ed25519_niels_fe64
#define GE_TABLE_COMB ama_ed25519_base_comb_fe64
#define GE_TABLE_ODD ama_ed25519_base_odd_fe64
#define GE_CONST_D ama_ed25519_const_d_fe64
#define GE_CONST_D2 ama_ed25519_const_d2_fe64
#define GE_CONST_SQRTM1 ama_ed25519_const_sqrtm1_fe64
#include "../internal/ama_ed25519_ge.h"

#else  /* not x86-64 GCC/Clang — emit nothing; the dispatcher never references this unit */

/* ISO C forbids an empty translation unit. */
int ama_ed25519_fe64_mulx_unavailable_marker(void);
int ama_ed25519_fe64_mulx_unavailable_marker(void) { return 0; }

#endif
