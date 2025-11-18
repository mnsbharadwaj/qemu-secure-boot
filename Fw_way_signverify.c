/********************************************************************
 * ECDSA P-384 Verification
 * - Montgomery mod n engine with sign bits in a global flags word
 * - Step 7 pipeline:
 *     Rx mod p -> Mont(p) roundtrip -> mod n -> Mont(n) roundtrip
 *     final scalar v compared with r
 *
 * Sign bit model:
 *   g_flags bit0 : sign of operand A (1 = negative)
 *   g_flags bit1 : sign of operand B (1 = negative)
 *   g_flags bit31: sign of RESULT (1 = negative)
 *
 * Magnitudes are always in 48-byte big-endian arrays.
 ********************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/*---------------------------------------------------------
 * Global flags word
 *--------------------------------------------------------*/
static uint32_t g_flags = 0;

#define FLAG_A_SIGN  (1u << 0)
#define FLAG_B_SIGN  (1u << 1)
#define FLAG_R_SIGN  (1u << 31)

/* Montgomery contexts */
static BN_MONT_CTX *g_mont_n = NULL;  /* for order n */
static BN_MONT_CTX *g_mont_p = NULL;  /* for field prime p */

/*---------------------------------------------------------
 * Helpers: canonical + symmetric printing
 *--------------------------------------------------------*/
static void to_canonical(BIGNUM *out, const BIGNUM *in,
                         const BIGNUM *mod, BN_CTX *ctx)
{
    BN_nnmod(out, in, mod, ctx);
}

static void to_symmetric(BIGNUM *out, const BIGNUM *in,
                         const BIGNUM *mod, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    BIGNUM *half  = BN_CTX_get(ctx);
    BN_nnmod(canon, in, mod, ctx);
    BN_rshift1(half, mod);

    if (BN_cmp(canon, half) > 0)
        BN_sub(out, canon, mod);
    else
        BN_copy(out, canon);

    BN_CTX_end(ctx);
}

static void print_bn_stage_mod(const char *label,
                               const BIGNUM *x,
                               const BIGNUM *mod,
                               BN_CTX *ctx)
{
    printf("\n=== %s ===\n", label);

    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    BN_nnmod(canon, x, mod, ctx);

    char *raw = BN_bn2hex(x);
    char *can = BN_bn2hex(canon);

    printf("Raw (signed): %s0x%s\n",
           BN_is_negative(x) ? "-" : "",
           BN_is_negative(x) ? raw+1 : raw);
    printf("Canonical mod: 0x%s\n", can);

    BIGNUM *sym = BN_new();
    to_symmetric(sym, x, mod, ctx);
    char *sy = BN_bn2hex(sym);
    printf("Symmetric    : %s0x%s\n",
           BN_is_negative(sym) ? "-" : "",
           BN_is_negative(sym) ? sy+1 : sy);

    BN_free(sym);
    OPENSSL_free(raw);
    OPENSSL_free(can);
    OPENSSL_free(sy);
    BN_CTX_end(ctx);
}

/*---------------------------------------------------------
 * Magnitude + sign-bit encode/decode for 48-byte words
 *--------------------------------------------------------*/

/* Decode 48-byte magnitude + sign bit in g_flags[mask] -> signed BIGNUM */
static BIGNUM *decode_mag_with_flag(const uint8_t m[48], uint32_t mask)
{
    BIGNUM *bn = BN_bin2bn(m, 48, NULL);
    if (!bn) return NULL;
    if (g_flags & mask) BN_set_negative(bn, 1);
    return bn;
}

/* Encode signed BIGNUM -> 48-byte magnitude, set/clear g_flags[mask] */
static void encode_bn_to_mag_and_flag(uint8_t out[48],
                                      const BIGNUM *bn,
                                      uint32_t mask)
{
    BIGNUM *mag = BN_dup(bn);
    if (!mag) return;

    if (BN_is_negative(mag)) {
        BN_set_negative(mag, 0);
        g_flags |= mask;
    } else {
        g_flags &= ~mask;
    }

    BN_bn2binpad(mag, out, 48);
    BN_free(mag);
}

/*---------------------------------------------------------
 * Montgomery multiply / exponent mod n
 * (core math in canonical domain; engine wrappers use sign bits)
 *--------------------------------------------------------*/

static void mont_mul_n(BIGNUM *r,
                       const BIGNUM *a,
                       const BIGNUM *b,
                       const BIGNUM *mod,
                       BN_CTX *ctx)
{
    BIGNUM *aM = BN_new();
    BIGNUM *bM = BN_new();
    BIGNUM *rM = BN_new();

    BN_to_montgomery(aM, a, g_mont_n, ctx);
    BN_to_montgomery(bM, b, g_mont_n, ctx);
    BN_mod_mul_montgomery(rM, aM, bM, g_mont_n, ctx);
    BN_from_montgomery(r, rM, g_mont_n, ctx);

    BN_free(aM);
    BN_free(bM);
    BN_free(rM);
}

static void mont_exp_n(BIGNUM *r,
                       const BIGNUM *base,
                       const BIGNUM *exp,
                       const BIGNUM *mod,
                       BN_CTX *ctx)
{
    BIGNUM *baseM = BN_new();
    BIGNUM *resM  = BN_new();
    BIGNUM *one   = BN_new();

    BN_to_montgomery(baseM, base, g_mont_n, ctx);
    BN_one(one);
    BN_to_montgomery(resM, one, g_mont_n, ctx);

    int bits = BN_num_bits(exp);
    for (int i = bits - 1; i >= 0; --i) {
        BN_mod_mul_montgomery(resM, resM, resM, g_mont_n, ctx);
        if (BN_is_bit_set(exp, i))
            BN_mod_mul_montgomery(resM, resM, baseM, g_mont_n, ctx);
    }

    BN_from_montgomery(r, resM, g_mont_n, ctx);

    BN_free(baseM);
    BN_free(resM);
    BN_free(one);
}

/*---------------------------------------------------------
 * "Engine" wrappers for mod-n multiply / exp using flags
 *   Inputs:
 *     a_mem, b_mem  - 48-byte magnitudes
 *     g_flags bit0  - sign of A
 *     g_flags bit1  - sign of B
 *   Output:
 *     out_mem       - 48-byte magnitude of symmetric result
 *     g_flags bit31 - sign of result
 *--------------------------------------------------------*/

static void engine_mul_n(uint8_t out_mem[48],
                         const uint8_t a_mem[48],
                         const uint8_t b_mem[48],
                         const BIGNUM *mod,
                         BN_CTX *ctx)
{
    BIGNUM *a_sym = decode_mag_with_flag(a_mem, FLAG_A_SIGN);
    BIGNUM *b_sym = decode_mag_with_flag(b_mem, FLAG_B_SIGN);
    BIGNUM *a     = BN_new();
    BIGNUM *b     = BN_new();
    BIGNUM *r     = BN_new();
    BIGNUM *r_sym = BN_new();

    to_canonical(a, a_sym, mod, ctx);
    to_canonical(b, b_sym, mod, ctx);

    print_bn_stage_mod("[engine MUL] A input", a_sym, mod, ctx);
    print_bn_stage_mod("[engine MUL] B input", b_sym, mod, ctx);

    mont_mul_n(r, a, b, mod, ctx);
    print_bn_stage_mod("[engine MUL] result canonical", r, mod, ctx);

    to_symmetric(r_sym, r, mod, ctx);
    if (BN_is_negative(r_sym)) g_flags |= FLAG_R_SIGN;
    else                       g_flags &= ~FLAG_R_SIGN;

    BIGNUM *mag = BN_dup(r_sym);
    BN_set_negative(mag, 0);
    BN_bn2binpad(mag, out_mem, 48);
    BN_free(mag);

    BN_free(a_sym); BN_free(b_sym);
    BN_free(a); BN_free(b);
    BN_free(r); BN_free(r_sym);
}

static void engine_exp_n(uint8_t out_mem[48],
                         const uint8_t base_mem[48],
                         const uint8_t exp_mem[48],
                         const BIGNUM *mod,
                         BN_CTX *ctx)
{
    BIGNUM *base_sym = decode_mag_with_flag(base_mem, FLAG_A_SIGN);
    BIGNUM *exp_sym  = decode_mag_with_flag(exp_mem,  FLAG_B_SIGN);
    BIGNUM *base     = BN_new();
    BIGNUM *exp      = BN_new();
    BIGNUM *r        = BN_new();
    BIGNUM *r_sym    = BN_new();

    to_canonical(base, base_sym, mod, ctx);
    to_canonical(exp,  exp_sym,  mod, ctx);

    print_bn_stage_mod("[engine EXP] base input", base_sym, mod, ctx);
    print_bn_stage_mod("[engine EXP] exp  input", exp_sym,  mod, ctx);

    mont_exp_n(r, base, exp, mod, ctx);
    print_bn_stage_mod("[engine EXP] result canonical", r, mod, ctx);

    to_symmetric(r_sym, r, mod, ctx);
    if (BN_is_negative(r_sym)) g_flags |= FLAG_R_SIGN;
    else                       g_flags &= ~FLAG_R_SIGN;

    BIGNUM *mag = BN_dup(r_sym);
    BN_set_negative(mag, 0);
    BN_bn2binpad(mag, out_mem, 48);
    BN_free(mag);

    BN_free(base_sym); BN_free(exp_sym);
    BN_free(base); BN_free(exp);
    BN_free(r); BN_free(r_sym);
}

/*---------------------------------------------------------
 * Two-term scalar multiply
 *   R = k1 * Q + k0 * G
 *--------------------------------------------------------*/
static void two_term_mul(EC_POINT *R,
                         const BIGNUM *k1,
                         const EC_POINT *Q,
                         const BIGNUM *k0,
                         const EC_GROUP *group,
                         BN_CTX *ctx)
{
    EC_POINT_mul(group, R, k0, Q, k1, ctx);
}

/*---------------------------------------------------------
 * Your test vectors
 *--------------------------------------------------------*/
static const uint8_t message[] = {
0xE7,0xFB,0x79,0x09,0x01,0xEE,0x53,0x7D,0x86,0xA7,0xE9,0xDB,0x55,0xA9,0xBE,0x8B,
0x12,0x58,0x08,0x6B,0x1D,0x11,0xA1,0x9C,0x8B,0x1B,0x99,0x49,0x78,0x39,0xEC,0x04,
0xF2,0x6F,0x25,0x9A,0xDA,0xBA,0x4E,0x7F,0xBC,0x64,0xF8,0x17,0xC2,0xD6,0x01,0x65,
0x5A,0x96,0x63,0x4C,0xA3,0x0A,0x29,0x0C,0x95,0x53,0xC4,0x4F,0x6E,0x0F,0xE1,0x7E,
0xBE,0xAC,0xB1,0x57,0x0E,0x18,0x21,0x76,0xA4,0xAC,0x75,0x46,0x1E,0x37,0xF0,0x4F,
0x6B,0x07,0x59,0x5A,0xB8,0xAA,0xB0,0xA4,0xC7,0x34,0xB2,0xFC,0x31,0xF3,0x2B,0x32,
0xAB,0x16,0x4E,0xB2,0x25,0x6D,0x6C,0xB3,0xF0,0x1C,0xF6,0x54,0xAE,0xF0,0x41,0x48,
0x4F,0xF5,0x43,0x99,0x42,0x8D,0x95,0x0D,0x5E,0xD7,0xC5,0x7B,0xCC,0x12,0x92,0x9B
};

static const uint8_t Q_bin[96] = {
0x5E,0xB8,0x69,0x6E,0x47,0x9F,0xE9,0x57,0xF1,0xF2,0xCB,0xCF,0xB1,0x09,0xA4,0xD2,
0xEA,0x0A,0x58,0xCE,0xDB,0xEB,0x70,0xA0,0x59,0x7E,0x5C,0x21,0x09,0x11,0x01,0xDD,
0x96,0x95,0xDB,0x07,0x23,0x7F,0xDF,0xC7,0xC5,0xC7,0x2C,0x55,0x7F,0xB5,0xB8,0x9B,
0x5F,0xC8,0x0C,0xF1,0x22,0xA6,0x31,0x5A,0x9F,0x80,0x97,0xBC,0xA3,0xBE,0xCD,0xF2,
0x72,0xCF,0x99,0xFF,0x20,0x41,0x94,0x37,0x38,0x14,0xAA,0x45,0xAD,0xE5,0x75,0x45,
0x95,0xDA,0x0B,0xEE,0x09,0x85,0x62,0x5C,0xF3,0x78,0x61,0x70,0x24,0x00,0x44,0x34
};

static const uint8_t sig_bin[96] = {
0x5B,0xBD,0x29,0x46,0xC5,0x8E,0xBF,0x5C,0x7D,0xFE,0xBD,0x5C,0xBE,0x5A,0x2D,0xC0,
0xF4,0xE7,0xA2,0xA3,0xB8,0xD2,0x63,0x53,0xF3,0xFC,0x54,0x58,0x9D,0x18,0x5F,0xDD,
0x75,0xC3,0x47,0x21,0x0D,0x9B,0xB2,0x81,0x23,0x41,0xD3,0x8E,0x14,0xA2,0x0F,0x2D,
0x90,0xAD,0xF5,0x21,0x2F,0x03,0x17,0xB2,0x61,0x39,0x35,0xAC,0x76,0x5F,0x90,0xF3,
0x72,0x56,0xB6,0xDC,0x0B,0x04,0x1C,0x33,0xE8,0x65,0xDE,0x34,0x44,0x21,0x44,0xD3,
0x10,0xE0,0xCB,0x6C,0x10,0x55,0x89,0xD8,0x60,0x63,0xCD,0xDB,0xD8,0x0A,0x96,0x15
};

/*---------------------------------------------------------
 * MAIN – ECDSA VERIFY WITH STEP-7 PIPELINE
 *--------------------------------------------------------*/
int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (!group) {
        fprintf(stderr, "EC_GROUP_new_by_curve_name failed\n");
        return 1;
    }

    /* Order n and prime p */
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);
    const BIGNUM *p = EC_GROUP_get0_field(group);

    printf("\n================ ECDSA VERIFY (Montgomery Engine + Step7) ================\n");

    /* Init Montgomery contexts */
    g_mont_n = BN_MONT_CTX_new();
    BN_MONT_CTX_set(g_mont_n, n, ctx);

    g_mont_p = BN_MONT_CTX_new();
    BN_MONT_CTX_set(g_mont_p, p, ctx);

    print_bn_stage_mod("Order n", n, n, ctx);
    print_bn_stage_mod("Prime p", (BIGNUM *)p, (BIGNUM *)p, ctx);

    /******** STEP 1: Load r and s ********/
    BIGNUM *r = BN_bin2bn(sig_bin,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin + 48, 48, NULL);

    print_bn_stage_mod("Input r", r, n, ctx);
    print_bn_stage_mod("Input s", s, n, ctx);

    /******** STEP 2: Hash the message ********/
    uint8_t hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);
    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_bn_stage_mod("SHA384(message) = e", e, n, ctx);

    /******** STEP 3: temp0 = n - 2 ********/
    BIGNUM *temp0 = BN_dup(n);
    BN_sub_word(temp0, 2);
    print_bn_stage_mod("temp0 = n-2", temp0, n, ctx);

    /******** STEP 4: temp1 = s^(n-2) mod n via engine EXP ********/
    uint8_t s_mem[48], temp0_mem[48], temp1_mem[48];

    encode_bn_to_mag_and_flag(s_mem,    s,     FLAG_A_SIGN);  /* base = s */
    encode_bn_to_mag_and_flag(temp0_mem,temp0, FLAG_B_SIGN);  /* exp  = n-2 */

    engine_exp_n(temp1_mem, s_mem, temp0_mem, n, ctx);

    BIGNUM *temp1_sym = decode_mag_with_flag(temp1_mem, FLAG_R_SIGN);
    BIGNUM *temp1     = BN_new();
    to_canonical(temp1, temp1_sym, n, ctx);
    print_bn_stage_mod("temp1 = s^(n-2)", temp1, n, ctx);

    /******** STEP 5: Scalars via engine MUL ********/
    BIGNUM *Scalar1 = BN_new();
    BIGNUM *Scalar0 = BN_new();
    uint8_t e_mem[48], temp1_mem2[48], Scalar1_mem[48], Scalar0_mem[48];

    /* Scalar1 = e * temp1 */
    encode_bn_to_mag_and_flag(e_mem,       e,      FLAG_A_SIGN);
    encode_bn_to_mag_and_flag(temp1_mem2,  temp1,  FLAG_B_SIGN);
    engine_mul_n(Scalar1_mem, e_mem, temp1_mem2, n, ctx);
    BIGNUM *Scalar1_sym = decode_mag_with_flag(Scalar1_mem, FLAG_R_SIGN);
    to_canonical(Scalar1, Scalar1_sym, n, ctx);
    print_bn_stage_mod("Scalar1 = e*temp1", Scalar1, n, ctx);

    /* Scalar0 = r * temp1 */
    encode_bn_to_mag_and_flag(s_mem,   r,      FLAG_A_SIGN);
    encode_bn_to_mag_and_flag(temp1_mem2, temp1, FLAG_B_SIGN);
    engine_mul_n(Scalar0_mem, s_mem, temp1_mem2, n, ctx);
    BIGNUM *Scalar0_sym = decode_mag_with_flag(Scalar0_mem, FLAG_R_SIGN);
    to_canonical(Scalar0, Scalar0_sym, n, ctx);
    print_bn_stage_mod("Scalar0 = r*temp1", Scalar0, n, ctx);

    /******** STEP 6: Point = Scalar1*Q + Scalar0*G ********/
    BIGNUM *Qx = BN_bin2bn(Q_bin,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    EC_POINT *R = EC_POINT_new(group);
    two_term_mul(R, Scalar1, Q, Scalar0, group, ctx);

    if (EC_POINT_is_at_infinity(group, R)) {
        printf("\n*** R is at infinity -> SIGNATURE INVALID ***\n");
        return 1;
    }

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);

    print_bn_stage_mod("R.x in field p", Rx, (BIGNUM *)p, ctx);

    /******** STEP 7: Your pipeline:
     *   - Rx_p = Rx mod p
     *   - Mont(p) round-trip: Rx_pM -> Rx_p_round
     *   - v0  = Rx_p_round mod n
     *   - Mont(n) round-trip: v0M -> v
     *   - compare v with r
     ********************************************************/
    BIGNUM *Rx_p       = BN_new();
    BIGNUM *Rx_pM      = BN_new();
    BIGNUM *Rx_p_round = BN_new();

    /* mod p */
    BN_nnmod(Rx_p, Rx, (BIGNUM *)p, ctx);
    print_bn_stage_mod("Rx reduced mod p", Rx_p, (BIGNUM *)p, ctx);

    /* Mont(p) round-trip */
    BN_to_montgomery(Rx_pM, Rx_p, g_mont_p, ctx);
    print_bn_stage_mod("Rx_p in Mont(p)", Rx_pM, (BIGNUM *)p, ctx);

    BN_from_montgomery(Rx_p_round, Rx_pM, g_mont_p, ctx);
    print_bn_stage_mod("Rx_p after Mont(p) round-trip", Rx_p_round, (BIGNUM *)p, ctx);

    /* Now move to order domain n and Mont(n) round-trip */
    BIGNUM *v0  = BN_new();
    BIGNUM *v0M = BN_new();
    BIGNUM *v   = BN_new();

    BN_nnmod(v0, Rx_p_round, n, ctx);
    print_bn_stage_mod("v0 = Rx_p_round mod n", v0, n, ctx);

    BN_to_montgomery(v0M, v0, g_mont_n, ctx);
    print_bn_stage_mod("v0 in Mont(n)", v0M, n, ctx);

    BN_from_montgomery(v, v0M, g_mont_n, ctx);
    print_bn_stage_mod("v after Mont(n) round-trip", v, n, ctx);

    /******** STEP 8: Final comparison ********/
    if (BN_cmp(v, r) == 0)
        printf("\n✔ SIGNATURE VALID (v == r)\n");
    else
        printf("\n✘ SIGNATURE INVALID (v != r)\n");

    return 0;
}
