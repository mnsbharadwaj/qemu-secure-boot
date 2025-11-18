#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/* ============================================================
 * Global flags: sign bits for operands and result
 *   bit0  -> operand A sign
 *   bit1  -> operand B sign
 *   bit31 -> RESULT sign
 *   1 = negative, 0 = non-negative
 * ========================================================== */

uint32_t g_flags = 0;

#define FLAG_A_SIGN   (1u << 0)
#define FLAG_B_SIGN   (1u << 1)
#define FLAG_R_SIGN   (1u << 31)

#define WORD_BYTES 48  /* 384-bit words (P-384 / n / p magnitudes) */

/* ============================================================
 * Montgomery context wrapper
 * ========================================================== */

typedef struct {
    BIGNUM      *mod;   /* modulus m */
    BN_MONT_CTX *mont;  /* Montgomery context */
} MONT_CTX_WR;

int mont_ctx_init(MONT_CTX_WR *mc, const BIGNUM *mod, BN_CTX *ctx)
{
    mc->mod  = BN_dup(mod);
    mc->mont = BN_MONT_CTX_new();
    if (!mc->mod || !mc->mont) return 0;
    if (!BN_MONT_CTX_set(mc->mont, mc->mod, ctx)) return 0;
    return 1;
}

void mont_ctx_free(MONT_CTX_WR *mc)
{
    if (mc->mod)  BN_free(mc->mod);
    if (mc->mont) BN_MONT_CTX_free(mc->mont);
    mc->mod  = NULL;
    mc->mont = NULL;
}

/* ============================================================
 * Signed encoding: [-m .. +m] using magnitude + sign bit
 * ========================================================== */

static BIGNUM *decode_signed(const uint8_t mem[WORD_BYTES],
                             uint32_t sign_mask)
{
    BIGNUM *bn = BN_bin2bn(mem, WORD_BYTES, NULL);
    if (!bn) return NULL;
    if (g_flags & sign_mask)
        BN_set_negative(bn, 1);
    else
        BN_set_negative(bn, 0);
    return bn;
}

static void encode_signed(uint8_t mem[WORD_BYTES],
                          const BIGNUM *val,
                          uint32_t sign_mask)
{
    BIGNUM *tmp = BN_dup(val);
    if (!tmp) return;

    if (BN_is_negative(tmp)) {
        BN_set_negative(tmp, 0);      /* store |val| */
        g_flags |= sign_mask;         /* sign = 1 */
    } else {
        g_flags &= ~sign_mask;        /* sign = 0 */
    }

    BN_bn2binpad(tmp, mem, WORD_BYTES);
    BN_free(tmp);
}

/* Canonical: any signed BIGNUM -> [0..mod-1] */
static void to_canonical(BIGNUM *out,
                         const BIGNUM *in,
                         const BIGNUM *mod,
                         BN_CTX *ctx)
{
    BN_nnmod(out, in, mod, ctx);
}

/* Debug print */
static void print_full(const char *label,
                       const BIGNUM *x,
                       const BIGNUM *mod,
                       BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    BN_nnmod(canon, x, mod, ctx);

    char *raw   = BN_bn2hex(x);
    char *c_hex = BN_bn2hex(canon);

    printf("%s\n", label);
    printf("  raw      = %s0x%s\n",
           BN_is_negative(x) ? "-" : "",
           BN_is_negative(x) ? raw+1 : raw);
    printf("  canonical= 0x%s\n", c_hex);

    OPENSSL_free(raw);
    OPENSSL_free(c_hex);
    BN_CTX_end(ctx);
}

/* ============================================================
 * Small Montgomery helpers (normal domain in/out)
 * ========================================================== */

static int mont_to(BIGNUM *rM,
                   const BIGNUM *a,
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    return BN_to_montgomery(rM, a, mc->mont, ctx);
}

static int mont_from(BIGNUM *r,
                     const BIGNUM *aM,
                     const MONT_CTX_WR *mc,
                     BN_CTX *ctx)
{
    return BN_from_montgomery(r, aM, mc->mont, ctx);
}

/* r = (a * b) mod m, using Montgomery inside */
static int mont_mul_norm(BIGNUM *r,
                         const BIGNUM *a,
                         const BIGNUM *b,
                         const MONT_CTX_WR *mc,
                         BN_CTX *ctx)
{
    int ok = 0;
    BN_CTX_start(ctx);
    BIGNUM *aM = BN_CTX_get(ctx);
    BIGNUM *bM = BN_CTX_get(ctx);
    BIGNUM *rM = BN_CTX_get(ctx);
    if (!rM) goto end;

    if (!BN_to_montgomery(aM, a, mc->mont, ctx)) goto end;
    if (!BN_to_montgomery(bM, b, mc->mont, ctx)) goto end;
    if (!BN_mod_mul_montgomery(rM, aM, bM, mc->mont, ctx)) goto end;
    if (!BN_from_montgomery(r, rM, mc->mont, ctx)) goto end;

    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

/* r = base^exp mod m (normal domain) using square-and-multiply */
static int mont_exp_norm(BIGNUM *r,
                         const BIGNUM *base,
                         const BIGNUM *exp,
                         const MONT_CTX_WR *mc,
                         BN_CTX *ctx)
{
    int ok = 0;
    BN_CTX_start(ctx);

    BIGNUM *baseM = BN_CTX_get(ctx);
    BIGNUM *resM  = BN_CTX_get(ctx);
    BIGNUM *one   = BN_CTX_get(ctx);
    if (!one) goto end;

    if (!BN_one(one)) goto end;
    if (!BN_to_montgomery(baseM, base, mc->mont, ctx)) goto end;
    if (!BN_to_montgomery(resM,  one,  mc->mont, ctx)) goto end;

    int bits = BN_num_bits(exp);
    for (int i = bits - 1; i >= 0; --i) {
        if (!BN_mod_mul_montgomery(resM, resM, resM, mc->mont, ctx)) goto end;
        if (BN_is_bit_set(exp, i)) {
            if (!BN_mod_mul_montgomery(resM, resM, baseM, mc->mont, ctx))
                goto end;
        }
    }

    if (!BN_from_montgomery(r, resM, mc->mont, ctx)) goto end;
    ok = 1;

end:
    BN_CTX_end(ctx);
    return ok;
}

/* ============================================================
 * FLAT ENGINE OPS (add, sub, mul, exp, scalar)
 * Each logs sign bits and uses -m..+m encoding.
 * ========================================================== */

/* ADD: R = (A + B) mod m */
int engine_add_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    printf("\n[ADD] g_flags=0x%08X A_sign=%d B_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *A   = BN_new();
    BIGNUM *B   = BN_new();
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !A || !B || !R) return 0;

    to_canonical(A, A_s, mc->mod, ctx);
    to_canonical(B, B_s, mc->mod, ctx);

    print_full("  A (decoded)", A_s, mc->mod, ctx);
    print_full("  B (decoded)", B_s, mc->mod, ctx);

    BN_mod_add(R, A, B, mc->mod, ctx);
    print_full("  R (canonical)", R, mc->mod, ctx);

    /* canonical => non-negative => result sign = 0 */
    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s);
    BN_free(A); BN_free(B); BN_free(R);
    return 1;
}

/* SUB: R = (A - B) mod m */
int engine_sub_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    printf("\n[SUB] g_flags=0x%08X A_sign=%d B_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *A   = BN_new();
    BIGNUM *B   = BN_new();
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !A || !B || !R) return 0;

    to_canonical(A, A_s, mc->mod, ctx);
    to_canonical(B, B_s, mc->mod, ctx);

    print_full("  A (decoded)", A_s, mc->mod, ctx);
    print_full("  B (decoded)", B_s, mc->mod, ctx);

    BN_mod_sub(R, A, B, mc->mod, ctx);
    print_full("  R (canonical)", R, mc->mod, ctx);

    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s);
    BN_free(A); BN_free(B); BN_free(R);
    return 1;
}

/* MUL: R = (A * B) mod m, using Montgomery */
int engine_mul_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    printf("\n[MUL] g_flags=0x%08X A_sign=%d B_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *A   = BN_new();
    BIGNUM *B   = BN_new();
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !A || !B || !R) return 0;

    to_canonical(A, A_s, mc->mod, ctx);
    to_canonical(B, B_s, mc->mod, ctx);

    print_full("  A (decoded)", A_s, mc->mod, ctx);
    print_full("  B (decoded)", B_s, mc->mod, ctx);

    if (!mont_mul_norm(R, A, B, mc, ctx)) {
        fprintf(stderr, "mont_mul_norm failed\n");
        return 0;
    }
    print_full("  R (canonical)", R, mc->mod, ctx);

    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);
    printf("
