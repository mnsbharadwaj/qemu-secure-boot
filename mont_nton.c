#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/* ============================================================
 * Global sign flags
 *   bit 0  -> operand A sign (1 = negative)
 *   bit 1  -> operand B sign (1 = negative)
 *   bit 31 -> RESULT sign (1 = negative)
 * ========================================================== */
static uint32_t g_flags = 0;

#define FLAG_A_SIGN   (1u << 0)
#define FLAG_B_SIGN   (1u << 1)
#define FLAG_R_SIGN   (1u << 31)

#define WORD_BYTES 48   /* 384-bit magnitudes */

/* ============================================================
 * Montgomery wrapper for a modulus
 * ========================================================== */
typedef struct {
    BIGNUM      *mod;   /* modulus m (odd) */
    BN_MONT_CTX *mont;  /* Montgomery context */
} MONT_CTX_WR;

static int mont_ctx_init(MONT_CTX_WR *mc, const BIGNUM *mod, BN_CTX *ctx)
{
    mc->mod  = BN_dup(mod);
    mc->mont = BN_MONT_CTX_new();
    if (!mc->mod || !mc->mont) return 0;
    if (!BN_MONT_CTX_set(mc->mont, mc->mod, ctx)) return 0;
    return 1;
}

static void mont_ctx_free(MONT_CTX_WR *mc)
{
    if (mc->mod)  BN_free(mc->mod);
    if (mc->mont) BN_MONT_CTX_free(mc->mont);
    mc->mod  = NULL;
    mc->mont = NULL;
}

/* ============================================================
 * Signed magnitude helpers: values in [-m .. +m]
 * ========================================================== */

/*  mem[48] + sign bit -> signed BIGNUM (±magnitude)  */
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

/* signed BN -> mem[48] + sign bit (1 = negative) */
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

/* Reduce a signed result into the range [-m .. +m]
 * using repeated add/sub of mod if necessary.
 */
static void signed_reduce(BIGNUM *r, const BIGNUM *mod, BN_CTX *ctx)
{
    (void)ctx; /* not used, but kept for symmetry */

    for (;;) {
        if (!BN_is_negative(r)) {
            /* r > m ? subtract m */
            int cmp = BN_cmp(r, mod);
            if (cmp <= 0) break;    /* r <= m */
            BN_sub(r, r, mod);
        } else {
            /* r < -m ? add m */
            if (BN_cmp_abs(r, mod) <= 0) break; /* |r| <= m */
            BN_add(r, r, mod);
        }
    }
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

/* ============================================================
 * ENGINE OPS
 *   - Inputs always encoded as signed [-m .. +m]
 *   - Outputs always reduced to [-m .. +m] and sign bit set
 * ========================================================== */

/* Modular ADD (signed):
 *   R = A + B, reduced to [-m .. +m]
 */
static int engine_mod_add(uint8_t memR[WORD_BYTES],
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
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_add(R, A_s, B_s);
    print_full("  A_s", A_s, mc->mod, ctx);
    print_full("  B_s", B_s, mc->mod, ctx);
    print_full("  R_raw = A_s + B_s", R, mc->mod, ctx);

    signed_reduce(R, mc->mod, ctx);
    print_full("  R_red ([-m..+m])", R, mc->mod, ctx);

    encode_signed(memR, R, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

/* Modular SUB (signed):
 *   R = A - B, reduced to [-m .. +m]
 */
static int engine_mod_sub(uint8_t memR[WORD_BYTES],
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
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_sub(R, A_s, B_s);
    print_full("  A_s", A_s, mc->mod, ctx);
    print_full("  B_s", B_s, mc->mod, ctx);
    print_full("  R_raw = A_s - B_s", R, mc->mod, ctx);

    signed_reduce(R, mc->mod, ctx);
    print_full("  R_red ([-m..+m])", R, mc->mod, ctx);

    encode_signed(memR, R, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

/* Montgomery MULT:
 *   Inputs: A_M, B_M are Mont residues, but with separate sign bits.
 *   Logical value = (sign ? -mag : +mag) in [-m..+m]
 *   We:
 *     - ignore sign for magnitude (take |A_M|, |B_M|)
 *     - run BN_mod_mul_montgomery on magnitudes
 *     - sign_out = signA XOR signB
 *     - encode signed result in [-m..+m]
 */
static int engine_mont_mul(uint8_t memR[WORD_BYTES],
                           const uint8_t memA[WORD_BYTES],
                           const uint8_t memB[WORD_BYTES],
                           const MONT_CTX_WR *mc,
                           BN_CTX *ctx)
{
    printf("\n[MONT_MUL] g_flags=0x%08X A_sign=%d B_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

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

    /* canonicalize magnitudes modulo m (still Mont residues) */
    BN_nnmod(A_mag, A_mag, mc->mod, ctx);
    BN_nnmod(B_mag, B_mag, mc->mod, ctx);

    print_full("  A_M (signed input)", A_s, mc->mod, ctx);
    print_full("  B_M (signed input)", B_s, mc->mod, ctx);

    /* Mont product: result is canonical 0..m-1 in Mont domain */
    if (!BN_mod_mul_montgomery(R_mag, A_mag, B_mag, mc->mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed\n");
        return 0;
    }
    print_full("  R_mag (Mont canonical)", R_mag, mc->mod, ctx);

    if (signR) BN_set_negative(R_mag, 1);  /* signed Mont result */

    /* |R_mag| <= m-1 < m, so already in [-m..+m] */
    print_full("  R_signed ([-m..+m])", R_mag, mc->mod, ctx);

    encode_signed(memR, R_mag, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s); BN_free(B_s);
    BN_free(A_mag); BN_free(B_mag); BN_free(R_mag);
    return 1;
}

/* Mont multiply by 1:
 *   R_M = A_M * 1_M  (still Mont domain)
 *   sign_out = sign(A)
 */
static int engine_mont_mul1(uint8_t memR[WORD_BYTES],
                            const uint8_t memA[WORD_BYTES],
                            const MONT_CTX_WR *mc,
                            BN_CTX *ctx)
{
    printf("\n[MONT_MUL1] g_flags=0x%08X A_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0);

    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    if (!A_s) return 0;

    int signA = BN_is_negative(A_s) ? 1 : 0;

    BIGNUM *A_mag = BN_dup(A_s);
    BIGNUM *R_mag = BN_new();
    BIGNUM *one   = BN_new();
    BIGNUM *oneM  = BN_new();
    if (!A_mag || !R_mag || !one || !oneM) return 0;

    BN_set_negative(A_mag, 0);
    BN_nnmod(A_mag, A_mag, mc->mod, ctx);
    BN_one(one);
    /* In HW: this would be Mont(1) precomputed. Here we call OpenSSL. */
    BN_to_montgomery(oneM, one, mc->mont, ctx);

    print_full("  A_M (signed input)", A_s, mc->mod, ctx);

    if (!BN_mod_mul_montgomery(R_mag, A_mag, oneM, mc->mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed (mul1)\n");
        return 0;
    }
    print_full("  R_mag (Mont canonical)", R_mag, mc->mod, ctx);

    if (signA) BN_set_negative(R_mag, 1);
    print_full("  R_signed ([-m..+m])", R_mag, mc->mod, ctx);

    encode_signed(memR, R_mag, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(A_s);
    BN_free(A_mag); BN_free(R_mag);
    BN_free(one); BN_free(oneM);
    return 1;
}

/* Mont EXP:
 *   base_M in Mont domain with sign bit
 *   exp    > 0 (normal integer, we use its absolute value)
 *   We do square-and-multiply in Mont domain on |base_M|,
 *   final sign = (sign(base) && exp is odd)
 */
static int engine_mont_exp(uint8_t memR[WORD_BYTES],
                           const uint8_t memBase[WORD_BYTES],
                           const uint8_t memExp[WORD_BYTES],
                           const MONT_CTX_WR *mc,
                           BN_CTX *ctx)
{
    printf("\n[MONT_EXP] g_flags=0x%08X base_sign=%d exp_sign=%d\n",
           g_flags,
           (g_flags & FLAG_A_SIGN)?1:0,
           (g_flags & FLAG_B_SIGN)?1:0);

    BIGNUM *B_s = decode_signed(memBase, FLAG_A_SIGN);
    BIGNUM *E_s = decode_signed(memExp,  FLAG_B_SIGN);
    if (!B_s || !E_s) return 0;

    int signB = BN_is_negative(B_s) ? 1 : 0;

    BIGNUM *B_M   = BN_dup(B_s);  /* Mont base magnitude */
    BIGNUM *E     = BN_dup(E_s);  /* exponent as positive integer */
    BIGNUM *R_M   = BN_new();
    if (!B_M || !E || !R_M) return 0;

    BN_set_negative(B_M, 0);
    BN_nnmod(B_M, B_M, mc->mod, ctx);
    BN_set_negative(E, 0);

    print_full("  base_M (signed input)", B_s, mc->mod, ctx);
    print_full("  exp (abs)", E, mc->mod, ctx);

    BN_CTX_start(ctx);
    BIGNUM *resM = BN_CTX_get(ctx);
    BIGNUM *one  = BN_CTX_get(ctx);
    if (!one) { BN_CTX_end(ctx); return 0; }

    BN_one(one);
    /* resM = Mont(1) */
    BN_to_montgomery(resM, one, mc->mont, ctx);

    int bits = BN_num_bits(E);
    for (int i = bits - 1; i >= 0; --i) {
        /* resM = resM^2 (Mont) */
        BN_mod_mul_montgomery(resM, resM, resM, mc->mont, ctx);
        if (BN_is_bit_set(E, i)) {
            BN_mod_mul_montgomery(resM, resM, B_M, mc->mont, ctx);
        }
    }
    BN_copy(R_M, resM);
    BN_CTX_end(ctx);

    print_full("  R_M (Mont canonical)", R_M, mc->mod, ctx);

    int exp_is_odd = BN_is_odd(E);
    if (signB && exp_is_odd)
        BN_set_negative(R_M, 1);

    /* |R_M| <= m-1, so already in [-m..+m] */
    print_full("  R_signed ([-m..+m])", R_M, mc->mod, ctx);

    encode_signed(memR, R_M, FLAG_R_SIGN);
    printf("  R_sign=%d g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN)?1:0, g_flags);

    BN_free(B_s); BN_free(E_s);
    BN_free(B_M); BN_free(E); BN_free(R_M);
    return 1;
}

/* ============================================================
 * Test vectors: your valid P-384 key + signature
 * ========================================================== */

static const unsigned char message[128] = {
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
 * MAIN: compare OpenSSL verify vs FW pipeline
 * ========================================================== */

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 1;

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (!group) return 1;

    /* Curve order n and prime p */
    BIGNUM *n = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    if (!n || !p || !a || !b) return 1;

    EC_GROUP_get_order(group, n, ctx);
    EC_GROUP_get_curve(group, p, a, b, ctx);

    print_full("Order n", n, n, ctx);
    print_full("Prime p", p, p, ctx);

    MONT_CTX_WR mont_n, mont_p;
    mont_ctx_init(&mont_n, n, ctx);
    mont_ctx_init(&mont_p, p, ctx);

    /* Public key Q */
    BIGNUM *Qx = BN_bin2bn(Q_bin_valid,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin_valid + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    /* r,s */
    BIGNUM *r = BN_bin2bn(sig_bin_valid,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin_valid + 48, 48, NULL);

    print_full("r", r, n, ctx);
    print_full("s", s, n, ctx);

    /* hash e = SHA384(message) */
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);
    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_full("e = SHA384(message)", e, n, ctx);

    /* 1) OpenSSL reference */
    printf("\n=== OpenSSL ECDSA_do_verify ===\n");
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_set_public_key(ec_key, Q);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_dup(r), BN_dup(s));
    int ok_ref = ECDSA_do_verify(hash, SHA384_DIGEST_LENGTH, sig, ec_key);
    printf("OpenSSL verify: %s\n", ok_ref == 1 ? "VALID" : "INVALID");

    /* 2) FW-style pipeline using our engine (Mont(n) domain for inverses) */
    printf("\n=== FW pipeline using engine_mont_* ===\n");

    /* Step1: w = s^(n-2) mod n via engine_mont_exp
       - First encode s into Mont(n) (magnitude only, sign 0) */
    printf("\n-- Step1: w = s^(n-2) mod n --\n");

    BIGNUM *s_can = BN_dup(s);
    BN_nnmod(s_can, s_can, n, ctx);

    BIGNUM *sM = BN_new();
    /* In HW: Mont(s) = mont_mul(s, R^2). Here we let OpenSSL do it. */
    BN_to_montgomery(sM, s_can, mont_n.mont, ctx);

    BIGNUM *exp_n2 = BN_dup(n);
    BN_sub_word(exp_n2, 2);

    uint8_t mem_base[WORD_BYTES] = {0};
    uint8_t mem_exp [WORD_BYTES] = {0};
    uint8_t mem_wM  [WORD_BYTES] = {0};

    g_flags = 0;
    encode_signed(mem_base, sM,      FLAG_A_SIGN);  /* base = sM */
    encode_signed(mem_exp,  exp_n2,  FLAG_B_SIGN);  /* exp  = n-2 */

    engine_mont_exp(mem_wM, mem_base, mem_exp, &mont_n, ctx);

    BIGNUM *wM_s = decode_signed(mem_wM, FLAG_R_SIGN);
    BIGNUM *wM   = BN_new();
    BN_set_negative(wM_s, 0);
    BN_nnmod(wM, wM_s, n, ctx);

    BIGNUM *w = BN_new();
    BN_from_montgomery(w, wM, mont_n.mont, ctx);
    print_full("w (s^{-1} mod n)", w, n, ctx);

    /* Step2: u1 = e*w mod n, u2 = r*w mod n using engine_mont_mul */
    printf("\n-- Step2: u1 = e*w, u2 = r*w (mod n) --\n");

    BIGNUM *eM  = BN_new();
    BIGNUM *wM2 = BN_new();
    BIGNUM *rM  = BN_new();
    BN_to_montgomery(eM, e, mont_n.mont, ctx);
    BN_to_montgomery(wM2,w, mont_n.mont, ctx);
    BN_to_montgomery(rM, r, mont_n.mont, ctx);

    uint8_t mem_eM [WORD_BYTES] = {0};
    uint8_t mem_wM2[WORD_BYTES] = {0};
    uint8_t mem_u1M[WORD_BYTES] = {0};
    uint8_t mem_u2M[WORD_BYTES] = {0};

    /* u1 = eM * wM2 */
    g_flags = 0;
    encode_signed(mem_eM,  eM,  FLAG_A_SIGN);  /* positive */
    encode_signed(mem_wM2, wM2, FLAG_B_SIGN);  /* positive */
    engine_mont_mul(mem_u1M, mem_eM, mem_wM2, &mont_n, ctx);

    BIGNUM *u1M_s = decode_signed(mem_u1M, FLAG_R_SIGN);
    BIGNUM *u1M   = BN_new();
    BN_set_negative(u1M_s, 0);
    BN_nnmod(u1M, u1M_s, n, ctx);

    BIGNUM *u1 = BN_new();
    BN_from_montgomery(u1, u1M, mont_n.mont, ctx);
    print_full("u1", u1, n, ctx);

    /* u2 = rM * wM2 */
    g_flags = 0;
    encode_signed(mem_eM,  rM,  FLAG_A_SIGN);
    encode_signed(mem_wM2, wM2, FLAG_B_SIGN);
    engine_mont_mul(mem_u2M, mem_eM, mem_wM2, &mont_n, ctx);

    BIGNUM *u2M_s = decode_signed(mem_u2M, FLAG_R_SIGN);
    BIGNUM *u2M   = BN_new();
    BN_set_negative(u2M_s, 0);
    BN_nnmod(u2M, u2M_s, n, ctx);

    BIGNUM *u2 = BN_new();
    BN_from_montgomery(u2, u2M, mont_n.mont, ctx);
    print_full("u2", u2, n, ctx);

    /* Step3: R = u1*G + u2*Q (normal EC math in F_p) */
    printf("\n-- Step3: EC R = u1*G + u2*Q --\n");
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);
    print_full("Rx", Rx, p, ctx);
    print_full("Ry", Ry, p, ctx);

    /* Step4: v = Rx mod n, compare with r */
    BIGNUM *v = BN_new();
    BN_nnmod(v, Rx, n, ctx);
    print_full("v = Rx mod n", v, n, ctx);

    int cmp = BN_cmp(v, r);
    printf("\nFW pipeline compare v ? r: %s\n",
           (cmp == 0) ? "EQUAL (VALID)" : "DIFFERENT (INVALID)");

    return 0;
}
