#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/*
 * Global status word:
 *   bit 0  -> sign of operand A (lsb0)
 *   bit 1  -> sign of operand B (lsb1)
 *   bit 31 -> sign of RESULT (msb0)
 *
 * 1 = negative, 0 = non-negative
 */
static uint32_t g_flags = 0;

#define FLAG_A_SIGN  (1u << 0)
#define FLAG_B_SIGN  (1u << 1)
#define FLAG_R_SIGN  (1u << 31)

/* Montgomery context for modulus n */
static BN_MONT_CTX *g_mont_n = NULL;

/*------------------------------------------------------------
 * Encoding / decoding: 48-byte magnitude + global sign bit
 *----------------------------------------------------------*/

/* Decode 48-byte magnitude + sign bit in g_flags[mask] -> signed BIGNUM */
static BIGNUM *decode_mag_with_flag(const uint8_t in[48], uint32_t mask)
{
    BIGNUM *bn = BN_bin2bn(in, 48, NULL);
    if (!bn) return NULL;

    if (g_flags & mask)
        BN_set_negative(bn, 1);
    return bn;
}

/* Encode signed BIGNUM -> 48-byte magnitude + update sign bit in g_flags[mask] */
static void encode_bn_to_mag_and_flag(uint8_t out[48],
                                      const BIGNUM *bn,
                                      uint32_t mask)
{
    BIGNUM *mag = BN_dup(bn);
    if (!mag) return;

    if (BN_is_negative(mag)) {
        BN_set_negative(mag, 0);   /* store |bn| as magnitude */
        g_flags |= mask;           /* set sign bit = 1 for negative */
    } else {
        g_flags &= ~mask;          /* clear sign bit for non-negative */
    }

    BN_bn2binpad(mag, out, 48);
    BN_free(mag);
}

/*------------------------------------------------------------
 * Canonical / symmetric helpers
 *----------------------------------------------------------*/

/* Any signed BIGNUM -> canonical [0 .. mod-1] */
static void to_canonical(BIGNUM *out,
                         const BIGNUM *in,
                         const BIGNUM *mod,
                         BN_CTX *ctx)
{
    BN_nnmod(out, in, mod, ctx);
}

/* Canonical -> symmetric in (-mod/2, +mod/2] for nicer viewing */
static void to_symmetric(BIGNUM *out,
                         const BIGNUM *in,
                         const BIGNUM *mod,
                         BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    BIGNUM *half  = BN_CTX_get(ctx);

    BN_nnmod(canon, in, mod, ctx);
    BN_rshift1(half, mod);

    if (BN_cmp(canon, half) > 0) {
        BN_sub(out, canon, mod);   /* negative near 0 */
    } else {
        BN_copy(out, canon);
    }

    BN_CTX_end(ctx);
}

/* Debug print: raw signed + canonical mod n */
static void print_bn_fullsym(const char *label,
                             const BIGNUM *x,
                             const BIGNUM *mod,
                             BN_CTX *ctx)
{
    printf("%s:\n", label);
    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    BN_nnmod(canon, x, mod, ctx);

    char *raw_hex   = BN_bn2hex(x);
    char *canon_hex = BN_bn2hex(canon);

    printf("  raw (signed)      = %s0x%s\n",
           BN_is_negative(x) ? "-" : "",
           BN_is_negative(x) ? raw_hex + 1 : raw_hex);
    printf("  canonical (mod n) = 0x%s\n", canon_hex);

    OPENSSL_free(raw_hex);
    OPENSSL_free(canon_hex);
    BN_CTX_end(ctx);
}

/*------------------------------------------------------------
 * Modular multiply and exponent "engine" with Montgomery
 *   External view: magnitudes + sign bits in g_flags
 *   Internal: canonical -> Montgomery -> compute -> normal
 *----------------------------------------------------------*/

/*
 * out_mem = (A * B) mod n, via:
 *   - read magnitudes from a_mem, b_mem
 *   - signs from g_flags bit0, bit1
 *   - canonicalize
 *   - convert to Montgomery
 *   - multiply in Montgomery
 *   - convert back to normal
 *   - map result to symmetric, store magnitude + sign bit31
 */
static void mod_mul_engine(uint8_t out_mem[48],
                           const uint8_t a_mem[48],
                           const uint8_t b_mem[48],
                           const BIGNUM *mod,
                           BN_CTX *ctx)
{
    if (!g_mont_n) {
        fprintf(stderr, "Montgomery ctx not initialized\n");
        return;
    }

    BIGNUM *a_sym = decode_mag_with_flag(a_mem, FLAG_A_SIGN);
    BIGNUM *b_sym = decode_mag_with_flag(b_mem, FLAG_B_SIGN);

    BIGNUM *a     = BN_new();
    BIGNUM *b     = BN_new();
    BIGNUM *aM    = BN_new();
    BIGNUM *bM    = BN_new();
    BIGNUM *rM    = BN_new();
    BIGNUM *r     = BN_new();
    BIGNUM *r_sym = BN_new();

    to_canonical(a, a_sym, mod, ctx);
    to_canonical(b, b_sym, mod, ctx);

    print_bn_fullsym("[MUL] a input", a_sym, mod, ctx);
    print_bn_fullsym("[MUL] b input", b_sym, mod, ctx);

    /* Convert to Montgomery domain */
    BN_to_montgomery(aM, a, g_mont_n, ctx);
    BN_to_montgomery(bM, b, g_mont_n, ctx);

    /* rM = aM * bM (Montgomery product) */
    BN_mod_mul_montgomery(rM, aM, bM, g_mont_n, ctx);

    /* Convert back to normal domain */
    BN_from_montgomery(r, rM, g_mont_n, ctx);
    print_bn_fullsym("[MUL] result canonical", r, mod, ctx);

    /* symmetric view + sign bit */
    to_symmetric(r_sym, r, mod, ctx);
    if (BN_is_negative(r_sym))
        g_flags |= FLAG_R_SIGN;
    else
        g_flags &= ~FLAG_R_SIGN;

    BIGNUM *mag = BN_dup(r_sym);
    BN_set_negative(mag, 0);
    BN_bn2binpad(mag, out_mem, 48);
    BN_free(mag);

    BN_free(a_sym); BN_free(b_sym);
    BN_free(a); BN_free(b);
    BN_free(aM); BN_free(bM);
    BN_free(rM); BN_free(r); BN_free(r_sym);
}

/*
 * out_mem = (base ^ exp) mod n:
 *   - decode base,exp with A/B sign bits
 *   - canonicalize
 *   - convert to Montgomery
 *   - square-and-multiply in Montgomery domain
 *   - convert back, map symmetric, store magnitude + sign bit31
 */
static void mod_exp_engine(uint8_t out_mem[48],
                           const uint8_t base_mem[48],
                           const uint8_t exp_mem[48],
                           const BIGNUM *mod,
                           BN_CTX *ctx)
{
    if (!g_mont_n) {
        fprintf(stderr, "Montgomery ctx not initialized\n");
        return;
    }

    BIGNUM *base_sym = decode_mag_with_flag(base_mem, FLAG_A_SIGN);
    BIGNUM *exp_sym  = decode_mag_with_flag(exp_mem,  FLAG_B_SIGN);

    BIGNUM *base  = BN_new();
    BIGNUM *exp   = BN_new();
    BIGNUM *baseM = BN_new();
    BIGNUM *resM  = BN_new();
    BIGNUM *r     = BN_new();
    BIGNUM *r_sym = BN_new();

    to_canonical(base, base_sym, mod, ctx);
    to_canonical(exp,  exp_sym,  mod, ctx);

    print_bn_fullsym("[EXP] base input", base_sym, mod, ctx);
    print_bn_fullsym("[EXP] exp  input", exp_sym,  mod, ctx);

    /* baseM = base in Montgomery domain */
    BN_to_montgomery(baseM, base, g_mont_n, ctx);

    /* resM = 1 in Montgomery domain */
    BIGNUM *one = BN_new();
    BN_one(one);
    BN_to_montgomery(resM, one, g_mont_n, ctx);

    int bits = BN_num_bits(exp);
    for (int i = bits - 1; i >= 0; --i) {
        /* resM = resM^2 mod n (Montgomery) */
        BN_mod_mul_montgomery(resM, resM, resM, g_mont_n, ctx);
        if (BN_is_bit_set(exp, i)) {
            /* resM = resM * baseM mod n */
            BN_mod_mul_montgomery(resM, resM, baseM, g_mont_n, ctx);
        }
    }

    /* Back to normal domain */
    BN_from_montgomery(r, resM, g_mont_n, ctx);
    print_bn_fullsym("[EXP] result canonical", r, mod, ctx);

    to_symmetric(r_sym, r, mod, ctx);
    if (BN_is_negative(r_sym))
        g_flags |= FLAG_R_SIGN;
    else
        g_flags &= ~FLAG_R_SIGN;

    BIGNUM *mag = BN_dup(r_sym);
    BN_set_negative(mag, 0);
    BN_bn2binpad(mag, out_mem, 48);
    BN_free(mag);

    BN_free(base_sym); BN_free(exp_sym);
    BN_free(base); BN_free(exp);
    BN_free(baseM); BN_free(resM);
    BN_free(r); BN_free(r_sym); BN_free(one);
}

/*------------------------------------------------------------
 * Your test vectors
 *----------------------------------------------------------*/

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

/*------------------------------------------------------------
 * MAIN – ECDSA verify using Montgomery-based engine
 *----------------------------------------------------------*/

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

    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);
    print_bn_fullsym("Order n", n, n, ctx);

    /* Initialize Montgomery context for n */
    g_mont_n = BN_MONT_CTX_new();
    if (!BN_MONT_CTX_set(g_mont_n, n, ctx)) {
        fprintf(stderr, "BN_MONT_CTX_set failed\n");
        return 1;
    }

    /* 1. Load canonical r, s */
    BIGNUM *r_can = BN_bin2bn(sig_bin,      48, NULL);
    BIGNUM *s_can = BN_bin2bn(sig_bin + 48, 48, NULL);

    print_bn_fullsym("r (canonical input)", r_can, n, ctx);
    print_bn_fullsym("s (canonical input)", s_can, n, ctx);

    /* 2. Put r, s into memory as magnitude + sign bits(A,B) */
    uint8_t r_mem[48], s_mem[48];
    encode_bn_to_mag_and_flag(r_mem, r_can, FLAG_A_SIGN);
    encode_bn_to_mag_and_flag(s_mem, s_can, FLAG_B_SIGN);

    /* Engine reads operands back */
    BIGNUM *r_in_sym = decode_mag_with_flag(r_mem, FLAG_A_SIGN);
    BIGNUM *s_in_sym = decode_mag_with_flag(s_mem, FLAG_B_SIGN);
    BIGNUM *r        = BN_new();
    BIGNUM *s        = BN_new();

    to_canonical(r, r_in_sym, n, ctx);
    to_canonical(s, s_in_sym, n, ctx);

    print_bn_fullsym("r (after mem decode)", r, n, ctx);
    print_bn_fullsym("s (after mem decode)", s, n, ctx);

    /* 3. e = SHA384(message) */
    uint8_t hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);
    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_bn_fullsym("e = SHA384(message)", e, n, ctx);

    /* 4. w = s^(n-2) mod n via mod_exp_engine */
    BIGNUM *exp_bn = BN_dup(n);
    BN_sub_word(exp_bn, 2);          /* n-2 */

    uint8_t base_mem[48], exp_mem[48], w_mem[48];
    encode_bn_to_mag_and_flag(base_mem, s,      FLAG_A_SIGN);  /* base = s */
    encode_bn_to_mag_and_flag(exp_mem,  exp_bn, FLAG_B_SIGN);  /* exp  = n-2 */

    mod_exp_engine(w_mem, base_mem, exp_mem, n, ctx);

    BIGNUM *w_sym = decode_mag_with_flag(w_mem, FLAG_R_SIGN);
    BIGNUM *w     = BN_new();
    to_canonical(w, w_sym, n, ctx);
    print_bn_fullsym("w = s^(n-2) mod n", w, n, ctx);

    /* 5. u1 = e*w mod n, u2 = r*w mod n via mod_mul_engine */
    uint8_t e_mem[48], w_mem2[48], u1_mem[48], u2_mem[48];

    /* u1 = e*w */
    encode_bn_to_mag_and_flag(e_mem,  e, FLAG_A_SIGN);
    encode_bn_to_mag_and_flag(w_mem2, w, FLAG_B_SIGN);
    mod_mul_engine(u1_mem, e_mem, w_mem2, n, ctx);

    BIGNUM *u1_sym = decode_mag_with_flag(u1_mem, FLAG_R_SIGN);
    BIGNUM *u1     = BN_new();
    to_canonical(u1, u1_sym, n, ctx);
    print_bn_fullsym("u1 = e*w", u1, n, ctx);

    /* u2 = r*w */
    encode_bn_to_mag_and_flag(r_mem,  r, FLAG_A_SIGN);
    encode_bn_to_mag_and_flag(w_mem2, w, FLAG_B_SIGN);
    mod_mul_engine(u2_mem, r_mem, w_mem2, n, ctx);

    BIGNUM *u2_sym = decode_mag_with_flag(u2_mem, FLAG_R_SIGN);
    BIGNUM *u2     = BN_new();
    to_canonical(u2, u2_sym, n, ctx);
    print_bn_fullsym("u2 = r*w", u2, n, ctx);

    /* 6. Load public key Q */
    BIGNUM *Qx = BN_bin2bn(Q_bin,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    /* 7. R = u1*G + u2*Q */
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    if (EC_POINT_is_at_infinity(group, R)) {
        printf("\nR is at infinity -> SIGNATURE INVALID\n");
        return 1;
    }

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);

    char *Rx_hex = BN_bn2hex(Rx);
    char *Ry_hex = BN_bn2hex(Ry);
    printf("\nR.x = %s\nR.y = %s\n", Rx_hex, Ry_hex);
    OPENSSL_free(Rx_hex);
    OPENSSL_free(Ry_hex);

    /* 8. v = Rx mod n */
    BIGNUM *v = BN_new();
    BN_nnmod(v, Rx, n, ctx);
    print_bn_fullsym("v = Rx mod n", v, n, ctx);

    /* Store v in memory (magnitude) + result sign bit (FLAG_R_SIGN) */
    uint8_t v_mem[48];
    BIGNUM *v_sym = BN_new();
    to_symmetric(v_sym, v, n, ctx);
    encode_bn_to_mag_and_flag(v_mem, v_sym, FLAG_R_SIGN);

    printf("\n[v magnitude in memory (48 bytes)]:\n");
    for (int i = 0; i < 48; ++i) printf("%02X", v_mem[i]);
    printf("\nResult sign bit (FLAG_R_SIGN) = %d\n",
           (g_flags & FLAG_R_SIGN) ? 1 : 0);

    /* 9. Compare v and r (canonical) -> signature valid/invalid */
    if (BN_cmp(v, r) == 0)
        printf("\n✔ SIGNATURE VALID (v == r)\n");
    else
        printf("\n✘ SIGNATURE INVALID (v != r)\n");

    return 0;
}
