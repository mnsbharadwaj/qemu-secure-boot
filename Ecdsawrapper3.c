#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/* ============================================================
 * Global sign flags:
 *   bit 0  -> operand A sign (1 = negative)
 *   bit 1  -> operand B sign (1 = negative)
 *   bit 31 -> RESULT sign (1 = negative)
 * ========================================================== */
static uint32_t g_flags = 0;

#define FLAG_A_SIGN   (1u << 0)
#define FLAG_B_SIGN   (1u << 1)
#define FLAG_R_SIGN   (1u << 31)

#define WORD_BYTES 48    /* 384 bits */

/* ============================================================
 * Signed magnitude helpers for [-m..+m]
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
        BN_set_negative(tmp, 0);
        g_flags |= sign_mask;
    } else {
        g_flags &= ~sign_mask;
    }

    BN_bn2binpad(tmp, mem, WORD_BYTES);
    BN_free(tmp);
}

/* Reduce signed result to the range [-m .. +m]
 * (only used for add/sub; Montgomery multiplies stay canonical with sign)
 */
static void signed_reduce(BIGNUM *r, const BIGNUM *mod, BN_CTX *ctx)
{
    (void)ctx;
    BIGNUM *abs = BN_dup(r);
    BN_set_negative(abs, 0);

    /* if r >  m: r = r - m */
    if (!BN_is_negative(r) && BN_cmp(r, mod) > 0) {
        BN_sub(r, r, mod);
        BN_free(abs);
        return;
    }

    /* if r < -m: r = r + m */
    if (BN_is_negative(r) && BN_ucmp(abs, mod) > 0) {
        BN_add(r, r, mod);
    }

    BN_free(abs);
}

/* Debug: print signed + canonical (mod m) */
static void print_full(const char *label,
                       const BIGNUM *x,
                       const BIGNUM *mod,
                       BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *canon = BN_CTX_get(ctx);
    if (!canon) { BN_CTX_end(ctx); return; }

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

static void print_bn_hex(const char *label, const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    printf("%s = 0x%s\n", label, hex);
    OPENSSL_free(hex);
}

static void print_bytes(const char *label,
                        const unsigned char *buf,
                        size_t len)
{
    printf("%s (%zu bytes) = ", label, len);
    for (size_t i = 0; i < len; ++i) printf("%02X", buf[i]);
    printf("\n");
}

/* ============================================================
 * ENGINE OPS (Add/Sub, MontMul, MontMul1, MontExp)
 * ========================================================== */

static int engine_mod_add(uint8_t memR[WORD_BYTES],
                          const uint8_t memA[WORD_BYTES],
                          const uint8_t memB[WORD_BYTES],
                          const BIGNUM *mod,
                          BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_add(R, A_s, B_s);
    signed_reduce(R, mod, ctx);
    encode_signed(memR, R, FLAG_R_SIGN);

    printf("\n[engine_mod_add]\n");
    print_full("  A_s", A_s, mod, ctx);
    print_full("  B_s", B_s, mod, ctx);
    print_full("  R",   R,   mod, ctx);
    printf("  R_signbit=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

static int engine_mod_sub(uint8_t memR[WORD_BYTES],
                          const uint8_t memA[WORD_BYTES],
                          const uint8_t memB[WORD_BYTES],
                          const BIGNUM *mod,
                          BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_sub(R, A_s, B_s);
    signed_reduce(R, mod, ctx);
    encode_signed(memR, R, FLAG_R_SIGN);

    printf("\n[engine_mod_sub]\n");
    print_full("  A_s", A_s, mod, ctx);
    print_full("  B_s", B_s, mod, ctx);
    print_full("  R",   R,   mod, ctx);
    printf("  R_signbit=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

/* Montgomery multiply wrapper
 * Inputs memA/memB represent signed Mont-domain values in [-m..+m]
 * Output memR is signed in [-m..+m], still in Mont-domain.
 */
static int engine_mont_mul(uint8_t memR[WORD_BYTES],
                           const uint8_t memA[WORD_BYTES],
                           const uint8_t memB[WORD_BYTES],
                           const BIGNUM *mod,
                           BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    if (!A_s || !B_s) return 0;

    int signA = BN_is_negative(A_s) ? 1 : 0;
    int signB = BN_is_negative(B_s) ? 1 : 0;
    int signR = signA ^ signB;

    BIGNUM *A_mag = BN_dup(A_s);
    BIGNUM *B_mag = BN_dup(B_s);
    BIGNUM *R_mag = BN_new();
    if (!A_mag || !B_mag || !R_mag) return 0;

    BN_set_negative(A_mag, 0);
    BN_set_negative(B_mag, 0);
    BN_nnmod(A_mag, A_mag, mod, ctx);
    BN_nnmod(B_mag, B_mag, mod, ctx);

    if (!BN_mod_mul_montgomery(R_mag, A_mag, B_mag, mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed\n");
        return 0;
    }

    if (signR) BN_set_negative(R_mag, 1);

    encode_signed(memR, R_mag, FLAG_R_SIGN);

    printf("\n[engine_mont_mul]\n");
    print_full("  A_s", A_s, mod, ctx);
    print_full("  B_s", B_s, mod, ctx);
    print_full("  R_mag (Mont, signed)", R_mag, mod, ctx);
    printf("  R_signbit=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s);
    BN_free(A_mag); BN_free(B_mag); BN_free(R_mag);
    return 1;
}

/* Montgomery multiply by 1 (still Mont-domain) */
static int engine_mont_mul1(uint8_t memR[WORD_BYTES],
                            const uint8_t memA[WORD_BYTES],
                            const BIGNUM *mod,
                            BN_MONT_CTX *mont,
                            BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    if (!A_s) return 0;

    int signA = BN_is_negative(A_s) ? 1 : 0;

    BIGNUM *A_mag = BN_dup(A_s);
    BIGNUM *R_mag = BN_new();
    BIGNUM *one   = BN_new();
    BIGNUM *oneM  = BN_new();
    if (!A_mag || !R_mag || !one || !oneM) return 0;

    BN_set_negative(A_mag, 0);
    BN_nnmod(A_mag, A_mag, mod, ctx);
    BN_one(one);
    BN_to_montgomery(oneM, one, mont, ctx);

    if (!BN_mod_mul_montgomery(R_mag, A_mag, oneM, mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed (mul1)\n");
        return 0;
    }

    if (signA) BN_set_negative(R_mag, 1);

    encode_signed(memR, R_mag, FLAG_R_SIGN);

    printf("\n[engine_mont_mul1]\n");
    print_full("  A_s", A_s, mod, ctx);
    print_full("  R_mag (Mont, signed)", R_mag, mod, ctx);
    printf("  R_signbit=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s);
    BN_free(A_mag); BN_free(R_mag);
    BN_free(one); BN_free(oneM);
    return 1;
}

/* Montgomery exp: base in Mont-domain, exponent positive integer (>0),
 * result in Mont-domain, signed via sign bit.
 */
static int engine_mont_exp(uint8_t memR[WORD_BYTES],
                           const uint8_t memBase[WORD_BYTES],
                           const uint8_t memExp[WORD_BYTES],
                           const BIGNUM *mod,
                           BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    printf("\n[engine_mont_exp] g_flags=0x%08X base_sign=%d exp_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

    BIGNUM *B_s = decode_signed(memBase, FLAG_A_SIGN);
    BIGNUM *E_s = decode_signed(memExp,  FLAG_B_SIGN);
    if (!B_s || !E_s) return 0;

    int signB = BN_is_negative(B_s) ? 1 : 0;

    BIGNUM *B_M = BN_dup(B_s);
    BIGNUM *E   = BN_dup(E_s);
    BIGNUM *R_M = BN_new();
    if (!B_M || !E || !R_M) return 0;

    BN_set_negative(B_M, 0);
    BN_nnmod(B_M, B_M, mod, ctx);
    BN_set_negative(E, 0);

    print_full("  base_M (signed input)", B_s, mod, ctx);
    print_full("  exp (abs)", E, mod, ctx);

    BN_CTX_start(ctx);
    BIGNUM *resM = BN_CTX_get(ctx);
    BIGNUM *one  = BN_CTX_get(ctx);
    if (!one) { BN_CTX_end(ctx); return 0; }

    BN_one(one);
    BN_to_montgomery(resM, one, mont, ctx);  /* resM = Mont(1) */

    int bits = BN_num_bits(E);
    printf("  exponent bits = %d\n", bits);

    for (int i = bits - 1; i >= 0; --i) {
        BN_mod_mul_montgomery(resM, resM, resM, mont, ctx);
        if (BN_is_bit_set(E, i)) {
            BN_mod_mul_montgomery(resM, resM, B_M, mont, ctx);
        }
    }
    BN_copy(R_M, resM);
    BN_CTX_end(ctx);

    print_full("  R_M (Mont canonical)", R_M, mod, ctx);

    int exp_is_odd = BN_is_odd(E);
    if (signB && exp_is_odd)
        BN_set_negative(R_M, 1);

    print_full("  R_signed ([-m..+m] in Mont)", R_M, mod, ctx);

    encode_signed(memR, R_M, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(B_s); BN_free(E_s);
    BN_free(B_M); BN_free(E); BN_free(R_M);
    return 1;
}

/* ============================================================
 * BN-level helpers that use wrappers for Mont conversions
 * ========================================================== */

/* normal x -> Mont(x) via wrapper:
 *   X_M = MontMul(x, R^2) = x * R^2 * R^-1 = x*R  mod m
 */
static BIGNUM *bn_to_mont_via_engine(const BIGNUM *x,
                                     const BIGNUM *R2,
                                     const BIGNUM *mod,
                                     BN_MONT_CTX *mont,
                                     BN_CTX *ctx)
{
    uint8_t memX[WORD_BYTES]  = {0};
    uint8_t memR2[WORD_BYTES] = {0};
    uint8_t memR[WORD_BYTES]  = {0};

    g_flags = 0;

    /* encode x and R2 as positive numbers */
    encode_signed(memX,  x,   FLAG_A_SIGN);
    encode_signed(memR2, R2,  FLAG_B_SIGN);

    engine_mont_mul(memR, memX, memR2, mod, mont, ctx);

    BIGNUM *X_M = decode_signed(memR, FLAG_R_SIGN);
    return X_M;
}

/* Mont(x) -> normal x via wrapper:
 *   x = MontMul(x_M, 1) = x_M * 1 * R^-1 = x  mod m
 */
static BIGNUM *bn_from_mont_via_engine(const BIGNUM *xM,
                                       const BIGNUM *mod,
                                       BN_MONT_CTX *mont,
                                       BN_CTX *ctx)
{
    uint8_t memX[WORD_BYTES]   = {0};
    uint8_t memOne[WORD_BYTES] = {0};
    uint8_t memR[WORD_BYTES]   = {0};

    BIGNUM *one = BN_new();
    BN_one(one);

    g_flags = 0;
    encode_signed(memX,   xM,  FLAG_A_SIGN);
    encode_signed(memOne, one, FLAG_B_SIGN);

    engine_mont_mul(memR, memX, memOne, mod, mont, ctx);

    BIGNUM *res = decode_signed(memR, FLAG_R_SIGN);
    BN_free(one);
    return res;
}

/* Mont EXP via engine at BN level */
static BIGNUM *bn_mont_exp_via_engine(const BIGNUM *B_M,
                                      const BIGNUM *E,
                                      const BIGNUM *mod,
                                      BN_MONT_CTX *mont,
                                      BN_CTX *ctx)
{
    uint8_t memB[WORD_BYTES] = {0};
    uint8_t memE[WORD_BYTES] = {0};
    uint8_t memR[WORD_BYTES] = {0};

    g_flags = 0;
    encode_signed(memB, B_M, FLAG_A_SIGN);   /* base in Mont */
    encode_signed(memE, E,   FLAG_B_SIGN);   /* exponent normal */

    engine_mont_exp(memR, memB, memE, mod, mont, ctx);

    BIGNUM *R_M = decode_signed(memR, FLAG_R_SIGN);
    return R_M;
}

/* Normal multiply via Mont wrappers:
 *   result = (a * b) mod m
 * implemented as:
 *   a_M = toMont(a)
 *   b_M = toMont(b)
 *   r_M = MontMul(a_M, b_M)
 *   r   = fromMont(r_M)
 */
static BIGNUM *bn_modmul_via_mont_wrappers(const BIGNUM *a,
                                           const BIGNUM *b,
                                           const BIGNUM *R2,
                                           const BIGNUM *mod,
                                           BN_MONT_CTX *mont,
                                           BN_CTX *ctx)
{
    uint8_t memA_M[WORD_BYTES] = {0};
    uint8_t memB_M[WORD_BYTES] = {0};
    uint8_t memR_M[WORD_BYTES] = {0};

    /* Convert a->a_M and b->b_M using bn_to_mont_via_engine */
    BIGNUM *a_M = bn_to_mont_via_engine(a, R2, mod, mont, ctx);
    BIGNUM *b_M = bn_to_mont_via_engine(b, R2, mod, mont, ctx);

    g_flags = 0;
    encode_signed(memA_M, a_M, FLAG_A_SIGN);
    encode_signed(memB_M, b_M, FLAG_B_SIGN);

    engine_mont_mul(memR_M, memA_M, memB_M, mod, mont, ctx);

    BIGNUM *r_M = decode_signed(memR_M, FLAG_R_SIGN);
    BIGNUM *r   = bn_from_mont_via_engine(r_M, mod, mont, ctx);

    BN_free(a_M); BN_free(b_M); BN_free(r_M);
    return r;
}

/* ============================================================
 * Your valid P-384 test vectors
 * ========================================================== */

static const unsigned char message_bytes[] = {
    0xE7,0xFB,0x79,0x09,0x01,0xEE,0x53,0x7D,0x86,0xA7,0xE9,0xDB,0x55,0xA9,0xBE,0x8B,
    0x12,0x58,0x08,0x6B,0x1D,0x11,0xA1,0x9C,0x8B,0x1B,0x99,0x49,0x78,0x39,0xEC,0x04,
    0xF2,0x6F,0x25,0x9A,0xDA,0xBA,0x4E,0x7F,0xBC,0x64,0xF8,0x17,0xC2,0xD6,0x01,0x65,
    0x5A,0x96,0x63,0x4C,0xA3,0x0A,0x29,0x0C,0x95,0x53,0xC4,0x4F,0x6E,0x0F,0xE1,0x7E,
    0xBE,0xAC,0xB1,0x57,0x0E,0x18,0x21,0x76,0xA4,0xAC,0x75,0x46,0x1E,0x37,0xF0,0x4F,
    0x6B,0x07,0x59,0x5A,0xB8,0xAA,0xB0,0xA4,0xC7,0x34,0xB2,0xFC,0x31,0xF3,0x2B,0x32,
    0xAB,0x16,0x4E,0xB2,0x25,0x6D,0x6C,0xB3,0xF0,0x1C,0xF6,0x54,0xAE,0xF0,0x41,0x48,
    0x4F,0xF5,0x43,0x99,0x42,0x8D,0x95,0x0D,0x5E,0xD7,0xC5,0x7B,0xCC,0x12,0x92,0x9B
};

static const unsigned char Q_bin_valid[96] = {
    0x55,0x8A,0x22,0x26,0xE9,0x71,0x41,0xC7,
    0xDE,0x91,0xE4,0x82,0x42,0xAF,0x06,0x68,
    0x93,0x50,0x25,0xFF,0x55,0x1C,0x7A,0xB1,
    0xEC,0x06,0xD6,0x93,0xE0,0x46,0xEE,0x02,
    0xA5,0x97,0xFC,0xC3,0x92,0x37,0x50,0x0A,
    0xEB,0xC6,0xC5,0xFE,0xCB,0x8B,0x65,0xEF,
    0xF8,0xAE,0xCE,0x51,0x31,0x38,0x4C,0x6A,
    0xAC,0xDD,0x4C,0x87,0x6E,0xDF,0x13,0xE8,
    0x1F,0x6A,0x63,0x70,0xB0,0x4F,0xA3,0xD2,
    0xD1,0x9C,0x87,0x9A,0x09,0xBB,0xE2,0x32,
    0xC4,0xDA,0x99,0xC6,0xFC,0x42,0xA2,0x78,
    0xC0,0x25,0x6C,0xF2,0xF5,0x20,0x17,0xF3,
};

static const unsigned char sig_bin_valid[96] = {
    0xF9,0x3A,0xA1,0x36,0x52,0xD3,0x82,0x35,
    0x33,0xB2,0x78,0xE7,0x8E,0x03,0x7B,0xF1,
    0x5A,0x9E,0x8E,0xC3,0x21,0x02,0xA0,0x6A,
    0xF6,0xC0,0x27,0x8F,0xB7,0x83,0xBF,0xCF,
    0xBB,0x00,0xD6,0x8A,0x20,0x38,0xCF,0x40,
    0x8C,0x57,0xD0,0x55,0x8C,0xAA,0xD9,0x80,
    0xD8,0x9B,0x67,0x60,0x41,0x48,0x53,0x2D,
    0xD5,0x7C,0x3C,0x41,0xA7,0x31,0xE0,0x05,
    0xDE,0x74,0x62,0x94,0x90,0xFE,0x0D,0x36,
    0x39,0x08,0xF8,0xB7,0x79,0xFE,0x42,0xB0,
    0x3E,0x93,0x7D,0x23,0x59,0x19,0x26,0x97,
    0x53,0x03,0x2D,0x99,0xB7,0x37,0x3F,0x8B,
};

/* ============================================================
 * MAIN – ECDSA verify using wrapper-based Mont engine
 * ========================================================== */

int main(void)
{
    int ret = 1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }

    /* --- Curve, order, mont ctx --- */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (!group) {
        fprintf(stderr, "EC_GROUP_new_by_curve_name failed\n");
        goto done;
    }

    BIGNUM *order = BN_new();
    if (!EC_GROUP_get_order(group, order, ctx)) {
        fprintf(stderr, "EC_GROUP_get_order failed\n");
        goto done;
    }
    printf("\n[Curve order]\n");
    print_bn_hex("n", order);

    BN_MONT_CTX *mont_n = BN_MONT_CTX_new();
    if (!BN_MONT_CTX_set(mont_n, order, ctx)) {
        fprintf(stderr, "BN_MONT_CTX_set failed for order\n");
        goto done;
    }

    /* Compute R (Montgomery base for n) and R^2 mod n (order_2) */
    BIGNUM *one = BN_new();
    BIGNUM *R_mod_n = BN_new();
    BIGNUM *R2_mod_n = BN_new();
    BN_one(one);
    BN_to_montgomery(R_mod_n, one, mont_n, ctx);              /* R mod n */
    BN_mod_mul(R2_mod_n, R_mod_n, R_mod_n, order, ctx);       /* R^2 mod n */

    printf("\n[Montgomery over order]\n");
    print_bn_hex("R mod n", R_mod_n);
    print_bn_hex("R^2 mod n (order_2)", R2_mod_n);

    /* --- Load public key Q --- */
    BIGNUM *Qx = BN_bin2bn(Q_bin_valid,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin_valid + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    if (!Qx || !Qy || !Q) {
        fprintf(stderr, "Failed to allocate Q\n");
        goto done;
    }
    if (!EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx)) {
        fprintf(stderr, "EC_POINT_set_affine_coordinates failed\n");
        goto done;
    }
    printf("\n[Public key Q]\n");
    print_bn_hex("Qx", Qx);
    print_bn_hex("Qy", Qy);

    /* --- Parse r, s --- */
    BIGNUM *r = BN_bin2bn(sig_bin_valid,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin_valid + 48, 48, NULL);

    printf("\n[Signature components]\n");
    print_bn_hex("r", r);
    print_bn_hex("s", s);

    /* --- Hash message and reduce e = H(m) mod n --- */
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(message_bytes, sizeof(message_bytes), hash);
    print_bytes("\nSHA384(message)", hash, SHA384_DIGEST_LENGTH);

    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    printf("\n[e before reduction]\n");
    print_bn_hex("e_raw", e);
    BN_nnmod(e, e, order, ctx);
    printf("[e after reduction mod n]\n");
    print_bn_hex("e", e);

    /* Check r,s in [1, n-1] */
    if (BN_is_zero(r) || BN_is_negative(r) || BN_cmp(r, order) >= 0) {
        printf("\n[r] out of range [1, n-1]\n");
        goto done;
    }
    if (BN_is_zero(s) || BN_is_negative(s) || BN_cmp(s, order) >= 0) {
        printf("\n[s] out of range [1, n-1]\n");
        goto done;
    }
    printf("\n[r] and [s] are in [1, n-1]\n");

    /* --- Compute w = s^(n-2) mod n using wrappers --- */
    BIGNUM *exp = BN_dup(order);
    BN_sub_word(exp, 2);     /* exp = n - 2 */
    printf("\n[Exponent for w]\n");
    print_bn_hex("n-2", exp);

    /* Convert s -> Mont(s) via wrapper (s_M) */
    BIGNUM *s_M = bn_to_mont_via_engine(s, R2_mod_n, order, mont_n, ctx);
    printf("\n[s_M = s in Mont(n) via wrappers]\n");
    print_full("s_M", s_M, order, ctx);

    /* w_M = s_M^(n-2) in Mont(n) */
    BIGNUM *w_M = bn_mont_exp_via_engine(s_M, exp, order, mont_n, ctx);
    printf("\n[w_M = s^(n-2) in Mont(n) via wrappers]\n");
    print_full("w_M", w_M, order, ctx);

    /* w = fromMont(w_M) */
    BIGNUM *w = bn_from_mont_via_engine(w_M, order, mont_n, ctx);
    BN_nnmod(w, w, order, ctx);
    printf("\n[w = s^(n-2) mod n (normal)]\n");
    print_full("w", w, order, ctx);

    /* --- Compute u1 = e*w mod n, u2 = r*w mod n using wrappers --- */
    BIGNUM *u1 = bn_modmul_via_mont_wrappers(e, w, R2_mod_n, order, mont_n, ctx);
    BIGNUM *u2 = bn_modmul_via_mont_wrappers(r, w, R2_mod_n, order, mont_n, ctx);

    BN_nnmod(u1, u1, order, ctx);
    BN_nnmod(u2, u2, order, ctx);

    printf("\n[u1, u2]\n");
    print_full("u1 = e*w mod n", u1, order, ctx);
    print_full("u2 = r*w mod n", u2, order, ctx);

    /* --- EC double scalar multiply: R = u1*G + u2*Q (mod P) --- */
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    EC_POINT *R = EC_POINT_new(group);
    if (!EC_POINT_mul(group, R, u1, Q, u2, ctx)) {
        fprintf(stderr, "EC_POINT_mul failed\n");
        goto done;
    }

    if (EC_POINT_is_at_infinity(group, R)) {
        printf("\nR is at infinity -> SIGNATURE INVALID\n");
        goto done;
    }

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    if (!EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx)) {
        fprintf(stderr, "EC_POINT_get_affine_coordinates failed\n");
        goto done;
    }

    printf("\n[EC point R = u1*G + u2*Q]\n");
    print_bn_hex("Rx", Rx);
    print_bn_hex("Ry", Ry);

    /* --- v = Rx mod n, compare with r --- */
    BIGNUM *v = BN_new();
    BN_nnmod(v, Rx, order, ctx);

    printf("\n[Final v and r]\n");
    print_full("v = Rx mod n", v, order, ctx);
    print_full("r (from signature)", r, order, ctx);

    if (BN_cmp(v, r) == 0) {
        printf("\n✅ SIGNATURE VALID (v == r)\n");
    } else {
        printf("\n❌ SIGNATURE INVALID (v != r)\n");
    }

    ret = 0;

done:
    if (ctx) BN_CTX_free(ctx);
    /* (OS will clean remaining allocations in a test program) */
    return ret;
}
