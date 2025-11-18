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
 * Montgomery wrapper
 * ========================================================== */

typedef struct {
    BIGNUM      *mod;   /* modulus m */
    BN_MONT_CTX *mont;  /* Montgomery context */
} MONT_CTX_WR;

/* Initialize Montgomery context for modulus m */
int mont_ctx_init(MONT_CTX_WR *mc, const BIGNUM *mod, BN_CTX *ctx)
{
    mc->mod  = BN_dup(mod);
    mc->mont = BN_MONT_CTX_new();
    if (!mc->mod || !mc->mont) return 0;
    if (!BN_MONT_CTX_set(mc->mont, mc->mod, ctx)) return 0;
    return 1;
}

/* Free Montgomery context */
void mont_ctx_free(MONT_CTX_WR *mc)
{
    if (mc->mod)  BN_free(mc->mod);
    if (mc->mont) BN_MONT_CTX_free(mc->mont);
    mc->mod  = NULL;
    mc->mont = NULL;
}

/* ============================================================
 * Encoding / decoding signed values (-m .. +m)
 *
 * We are NOT doing symmetric folding around m/2 internally.
 * We just support +/- magnitude via sign bit.
 *
 * Encoding:
 *   memory: big-endian |value|
 *   sign bit: 1 = negative, 0 = non-negative
 * Decoding:
 *   sign bit -> BN_set_negative(bn, 1/0)
 * ========================================================== */

/* Decode magnitude + sign bit into signed BIGNUM */
static BIGNUM *decode_signed(const uint8_t mem[WORD_BYTES],
                             uint32_t sign_mask)
{
    BIGNUM *bn = BN_bin2bn(mem, WORD_BYTES, NULL);
    if (!bn) return NULL;

    if (g_flags & sign_mask) {
        BN_set_negative(bn, 1);   /* negative */
    } else {
        BN_set_negative(bn, 0);   /* non-negative */
    }
    return bn;
}

/* Encode BIGNUM (possibly negative) into magnitude + set/clear sign bit */
static void encode_signed(uint8_t mem[WORD_BYTES],
                          const BIGNUM *val,
                          uint32_t sign_mask)
{
    BIGNUM *tmp = BN_dup(val);
    if (!tmp) return;

    if (BN_is_negative(tmp)) {
        BN_set_negative(tmp, 0);      /* store |val| */
        g_flags |= sign_mask;         /* sign bit = 1 */
    } else {
        g_flags &= ~sign_mask;        /* sign bit = 0 */
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

/* Debug: print raw & canonical */
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
 * Montgomery primitives
 * ========================================================== */

/* normal -> Montgomery (aM = a*R mod m) */
static int mont_to(BIGNUM *rM,
                   const BIGNUM *a,
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    return BN_to_montgomery(rM, a, mc->mont, ctx);
}

/* Montgomery -> normal (r = aM*R^{-1} mod m) */
static int mont_from(BIGNUM *r,
                     const BIGNUM *aM,
                     const MONT_CTX_WR *mc,
                     BN_CTX *ctx)
{
    return BN_from_montgomery(r, aM, mc->mont, ctx);
}

/* rM = aM + bM (Mont domain add) */
static int mont_add(BIGNUM *rM,
                    const BIGNUM *aM,
                    const BIGNUM *bM,
                    const MONT_CTX_WR *mc)
{
    return BN_mod_add(rM, aM, bM, mc->mod, NULL);
}

/* rM = aM - bM (Mont domain sub) */
static int mont_sub(BIGNUM *rM,
                    const BIGNUM *aM,
                    const BIGNUM *bM,
                    const MONT_CTX_WR *mc)
{
    return BN_mod_sub(rM, aM, bM, mc->mod, NULL);
}

/* rM = aM * bM (Montgomery product in Mont domain) */
static int mont_mul(BIGNUM *rM,
                    const BIGNUM *aM,
                    const BIGNUM *bM,
                    const MONT_CTX_WR *mc,
                    BN_CTX *ctx)
{
    return BN_mod_mul_montgomery(rM, aM, bM, mc->mont, ctx);
}

/* r = (a * b) mod m in NORMAL domain, using Mont internally */
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

    if (!mont_to(aM, a, mc, ctx)) goto end;
    if (!mont_to(bM, b, mc, ctx)) goto end;
    if (!mont_mul(rM, aM, bM, mc, ctx)) goto end;
    if (!mont_from(r, rM, mc, ctx)) goto end;

    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

/* r = base^exp mod m in NORMAL domain via Mont square-and-multiply */
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
    if (!mont_to(baseM, base, mc, ctx)) goto end;
    if (!mont_to(resM, one, mc, ctx)) goto end;

    int bits = BN_num_bits(exp);
    for (int i = bits - 1; i >= 0; --i) {
        if (!mont_mul(resM, resM, resM, mc, ctx)) goto end;   /* resM = resM^2 */
        if (BN_is_bit_set(exp, i)) {
            if (!mont_mul(resM, resM, baseM, mc, ctx)) goto end;
        }
    }

    if (!mont_from(r, resM, mc, ctx)) goto end;

    ok = 1;
end:
    BN_CTX_end(ctx);
    return ok;
}

/* ============================================================
 * ENGINE WRAPPERS for mod-m operations
 *
 * Inputs: memA, memB (magnitudes), sign bits in g_flags[bit0,bit1]
 * Output: memR, sign bit in bit31
 *
 * For modular ops, we produce canonical 0..m-1, so result sign=0.
 * Still consistent with allowed range -m..m.
 * ========================================================== */

typedef int (*binary_core_fn)(BIGNUM *R,
                              const BIGNUM *A,
                              const BIGNUM *B,
                              const MONT_CTX_WR *mc,
                              BN_CTX *ctx);

/* Core ops (mod m) using Mont where needed */

/* R = (A + B) mod m */
static int core_add(BIGNUM *R,
                    const BIGNUM *A,
                    const BIGNUM *B,
                    const MONT_CTX_WR *mc,
                    BN_CTX *ctx)
{
    (void)ctx;
    return BN_mod_add(R, A, B, mc->mod, NULL);
}

/* R = (A - B) mod m */
static int core_sub(BIGNUM *R,
                    const BIGNUM *A,
                    const BIGNUM *B,
                    const MONT_CTX_WR *mc,
                    BN_CTX *ctx)
{
    (void)ctx;
    return BN_mod_sub(R, A, B, mc->mod, NULL);
}

/* R = (A * B) mod m using Montgomery multiplication */
static int core_mul(BIGNUM *R,
                    const BIGNUM *A,
                    const BIGNUM *B,
                    const MONT_CTX_WR *mc,
                    BN_CTX *ctx)
{
    return mont_mul_norm(R, A, B, mc, ctx);
}

/* Shared binary engine: decode, canonicalize, compute, encode, log signs */
static int engine_binary_op(uint8_t memR[WORD_BYTES],
                            const uint8_t memA[WORD_BYTES],
                            const uint8_t memB[WORD_BYTES],
                            const MONT_CTX_WR *mc,
                            BN_CTX *ctx,
                            binary_core_fn op,
                            const char *label)
{
    int ok = 0;

    int A_sign_in = (g_flags & FLAG_A_SIGN) ? 1 : 0;
    int B_sign_in = (g_flags & FLAG_B_SIGN) ? 1 : 0;

    printf("\n%s: g_flags=0x%08X  A_sign=%d  B_sign=%d\n",
           label, g_flags, A_sign_in, B_sign_in);

    BIGNUM *A_signed = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_signed = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *A        = BN_new();
    BIGNUM *B        = BN_new();
    BIGNUM *R        = BN_new();

    if (!A_signed || !B_signed || !A || !B || !R) goto end;

    /* canonical inputs */
    to_canonical(A, A_signed, mc->mod, ctx);
    to_canonical(B, B_signed, mc->mod, ctx);

    print_full("   A (decoded)", A_signed, mc->mod, ctx);
    print_full("   B (decoded)", B_signed, mc->mod, ctx);

    if (!op(R, A, B, mc, ctx)) goto end;

    print_full("   R (canonical)", R, mc->mod, ctx);

    /* result is canonical 0..m-1, so sign bit = 0 */
    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);

    int R_sign_out = (g_flags & FLAG_R_SIGN) ? 1 : 0;
    printf("   Result sign (FLAG_R_SIGN) = %d, g_flags=0x%08X\n",
           R_sign_out, g_flags);

    ok = 1;

end:
    if (A_signed) BN_free(A_signed);
    if (B_signed) BN_free(B_signed);
    if (A) BN_free(A);
    if (B) BN_free(B);
    if (R) BN_free(R);
    return ok;
}

/* Public engine APIs */

int engine_add_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    return engine_binary_op(memR, memA, memB, mc, ctx, core_add, "[ADD]");
}

int engine_sub_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    return engine_binary_op(memR, memA, memB, mc, ctx, core_sub, "[SUB]");
}

int engine_mul_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memA[WORD_BYTES],
                   const uint8_t memB[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    return engine_binary_op(memR, memA, memB, mc, ctx, core_mul, "[MUL]");
}

/* Exponent engine: R = base^exp mod m in normal domain (canonical),
 * with sign-bit logging.
 */
int engine_exp_mod(uint8_t memR[WORD_BYTES],
                   const uint8_t memBase[WORD_BYTES],
                   const uint8_t memExp[WORD_BYTES],
                   const MONT_CTX_WR *mc,
                   BN_CTX *ctx)
{
    int ok = 0;

    int B_sign_in = (g_flags & FLAG_A_SIGN) ? 1 : 0;
    int E_sign_in = (g_flags & FLAG_B_SIGN) ? 1 : 0;

    printf("\n[EXP]: g_flags=0x%08X  base_sign(A)=%d  exp_sign(B)=%d\n",
           g_flags, B_sign_in, E_sign_in);

    BIGNUM *B_signed = decode_signed(memBase, FLAG_A_SIGN);
    BIGNUM *E_signed = decode_signed(memExp,  FLAG_B_SIGN);
    BIGNUM *B        = BN_new();
    BIGNUM *E        = BN_new();
    BIGNUM *R        = BN_new();

    if (!B_signed || !E_signed || !B || !E || !R) goto end;

    to_canonical(B, B_signed, mc->mod, ctx);
    to_canonical(E, E_signed, mc->mod, ctx);

    print_full("   [EXP] base (decoded)", B_signed, mc->mod, ctx);
    print_full("   [EXP] exp  (decoded)", E_signed, mc->mod, ctx);

    if (!mont_exp_norm(R, B, E, mc, ctx)) goto end;

    print_full("   [EXP] R (canonical)", R, mc->mod, ctx);

    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);
    printf("   [EXP] Result sign (FLAG_R_SIGN) = %d, g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN) ? 1 : 0, g_flags);

    ok = 1;

end:
    if (B_signed) BN_free(B_signed);
    if (E_signed) BN_free(E_signed);
    if (B) BN_free(B);
    if (E) BN_free(E);
    if (R) BN_free(R);
    return ok;
}

/* Scalar multiply in Z_m: R = K*A mod m (normal integer, NOT EC scalar mul),
 * with sign-bit logging.
 */
int engine_scalar_mul_mod(uint8_t memR[WORD_BYTES],
                          const uint8_t memK[WORD_BYTES],
                          const uint8_t memA[WORD_BYTES],
                          const MONT_CTX_WR *mc,
                          BN_CTX *ctx)
{
    int ok = 0;

    int K_sign_in = (g_flags & FLAG_A_SIGN) ? 1 : 0;
    int A_sign_in = (g_flags & FLAG_B_SIGN) ? 1 : 0;

    printf("\n[SCALAR]: g_flags=0x%08X  K_sign(A)=%d  A_sign(B)=%d\n",
           g_flags, K_sign_in, A_sign_in);

    BIGNUM *K_signed = decode_signed(memK, FLAG_A_SIGN);
    BIGNUM *A_signed = decode_signed(memA, FLAG_B_SIGN);
    BIGNUM *K        = BN_new();
    BIGNUM *A        = BN_new();
    BIGNUM *R        = BN_new();

    if (!K_signed || !A_signed || !K || !A || !R) goto end;

    to_canonical(K, K_signed, mc->mod, ctx);
    to_canonical(A, A_signed, mc->mod, ctx);

    print_full("   [SCALAR] K (decoded)", K_signed, mc->mod, ctx);
    print_full("   [SCALAR] A (decoded)", A_signed, mc->mod, ctx);

    if (!mont_mul_norm(R, K, A, mc, ctx)) goto end;

    print_full("   [SCALAR] R (canonical)", R, mc->mod, ctx);

    g_flags &= ~FLAG_R_SIGN;
    encode_signed(memR, R, FLAG_R_SIGN);
    printf("   [SCALAR] Result sign (FLAG_R_SIGN) = %d, g_flags=0x%08X\n",
           (g_flags & FLAG_R_SIGN) ? 1 : 0, g_flags);

    ok = 1;

end:
    if (K_signed) BN_free(K_signed);
    if (A_signed) BN_free(A_signed);
    if (K) BN_free(K);
    if (A) BN_free(A);
    if (R) BN_free(R);
    return ok;
}

/* ============================================================
 * Test vectors: message, valid Q, valid signature (r,s)
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
    0x53,0x03,0x2D,0x99,0xB7,0x37,0x3F,0x8B
};

/* ============================================================
 * MAIN: compare OpenSSL vs FW-style pipeline using engine_*
 * ========================================================== */

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

    /* Curve order n and prime p */
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_GROUP_get_curve(group, p, a, b, ctx);

    print_full("Order n", n, n, ctx);
    print_full("Prime p", p, p, ctx);

    /* Initialize Montgomery contexts for n and p */
    MONT_CTX_WR mont_n, mont_p;
    mont_ctx_init(&mont_n, n, ctx);
    mont_ctx_init(&mont_p, p, ctx);

    /* Load public key Q */
    BIGNUM *Qx = BN_bin2bn(Q_bin_valid,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin_valid + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    /* Load r, s */
    BIGNUM *r = BN_bin2bn(sig_bin_valid,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin_valid + 48, 48, NULL);
    print_full("r", r, n, ctx);
    print_full("s", s, n, ctx);

    /* Hash message: e = SHA384(message) */
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);
    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_full("e = SHA384(message)", e, n, ctx);

    /* --------------------------------------------------------
     * 1) OpenSSL reference verification
     * ------------------------------------------------------ */
    printf("\n=== OpenSSL ECDSA_do_verify ===\n");
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_set_public_key(ec_key, Q);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_dup(r), BN_dup(s));

    int ok_ref = ECDSA_do_verify(hash, SHA384_DIGEST_LENGTH, sig, ec_key);
    printf("OpenSSL verify: %s\n", ok_ref == 1 ? "VALID" : "INVALID");

    /* --------------------------------------------------------
     * 2) FW pipeline using engine_* (mod-n) + EC ops (mod-p)
     * ------------------------------------------------------ */

    printf("\n=== FW-style pipeline using Montgomery engine ===\n");

    uint8_t mem_s[WORD_BYTES]   = {0};
    uint8_t mem_exp[WORD_BYTES] = {0};
    uint8_t mem_w[WORD_BYTES]   = {0};

    /* Step 1: w = s^(n-2) mod n via engine_exp_mod */

    BIGNUM *exp_n2 = BN_dup(n);
    BN_sub_word(exp_n2, 2);

    /* Encode s and (n-2) as +/- magnitudes with sign bits 0 */
    g_flags = 0;
    encode_signed(mem_s,   s,       FLAG_A_SIGN);
    encode_signed(mem_exp, exp_n2,  FLAG_B_SIGN);

    printf("\n-- Step 1: w = s^(n-2) mod n --\n");
    engine_exp_mod(mem_w, mem_s, mem_exp, &mont_n, ctx);

    BIGNUM *w_signed = decode_signed(mem_w, FLAG_R_SIGN);
    BIGNUM *w        = BN_new();
    to_canonical(w, w_signed, n, ctx);
    print_full("w", w, n, ctx);

    /* Step 2: u1 = e*w mod n, u2 = r*w mod n via engine_mul_mod */

    uint8_t mem_e[WORD_BYTES]   = {0};
    uint8_t mem_w2[WORD_BYTES]  = {0};
    uint8_t mem_u1[WORD_BYTES]  = {0};
    uint8_t mem_u2[WORD_BYTES]  = {0};

    /* u1 = e*w */
    encode_signed(mem_e,  e, FLAG_A_SIGN);
    encode_signed(mem_w2, w, FLAG_B_SIGN);

    printf("\n-- Step 2a: u1 = e*w mod n --\n");
    engine_mul_mod(mem_u1, mem_e, mem_w2, &mont_n, ctx);

    BIGNUM *u1_signed = decode_signed(mem_u1, FLAG_R_SIGN);
    BIGNUM *u1        = BN_new();
    to_canonical(u1, u1_signed, n, ctx);
    print_full("u1", u1, n, ctx);

    /* u2 = r*w */
    encode_signed(mem_e,  r, FLAG_A_SIGN);
    encode_signed(mem_w2, w, FLAG_B_SIGN);

    printf("\n-- Step 2b: u2 = r*w mod n --\n");
    engine_mul_mod(mem_u2, mem_e, mem_w2, &mont_n, ctx);

    BIGNUM *u2_signed = decode_signed(mem_u2, FLAG_R_SIGN);
    BIGNUM *u2        = BN_new();
    to_canonical(u2, u2_signed, n, ctx);
    print_full("u2", u2, n, ctx);

    /* Step 3: EC double scalar multiply R = u1*G + u2*Q over F_p */

    printf("\n-- Step 3: EC double scalar multiply (mod P) --\n");
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    BIGNUM *Rx_aff = BN_new();
    BIGNUM *Ry_aff = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx_aff, Ry_aff, ctx);

    print_full("Rx_aff", Rx_aff, p, ctx);
    print_full("Ry_aff", Ry_aff, p, ctx);

    /* Step 4: Hardware-style pipeline:
       Rx_MP (Mont P) -> normal P -> Mont N -> normal N
     */

    printf("\n-- Step 4: HW-style MontP -> normalP -> MontN -> normalN --\n");

    BIGNUM *Rx_MP    = BN_new();
    BIGNUM *Rx_Pnorm = BN_new();
    BIGNUM *Rx_MN    = BN_new();
    BIGNUM *Rx_Nnorm = BN_new();

    /* emulate point core returning X in Mont(P) */
    mont_to(Rx_MP, Rx_aff, &mont_p, ctx);
    print_full("Rx_MP (Mont P)", Rx_MP, p, ctx);

    mont_from(Rx_Pnorm, Rx_MP, &mont_p, ctx);
    print_full("Rx_Pnorm (normal P)", Rx_Pnorm, p, ctx);

    mont_to(Rx_MN, Rx_Pnorm, &mont_n, ctx);
    print_full("Rx_MN (Mont N)", Rx_MN, n, ctx);

    mont_from(Rx_Nnorm, Rx_MN, &mont_n, ctx);
    print_full("Rx_Nnorm (normal N)", Rx_Nnorm, n, ctx);

    /* Step 5: encode Rx_Nnorm into mem_v and compare raw with r */

    uint8_t mem_v[WORD_BYTES]     = {0};
    uint8_t mem_r_ref[WORD_BYTES] = {0};

    /* result encoding (canonical, sign=0) */
    encode_signed(mem_v, Rx_Nnorm, FLAG_R_SIGN);
    int sign_v = (g_flags & FLAG_R_SIGN) ? 1 : 0;

    /* reference r encoding for raw-compare: canonical, sign=0 */
    BIGNUM *r_nonneg = BN_dup(r);
    BN_set_negative(r_nonneg, 0);
    BN_bn2binpad(r_nonneg, mem_r_ref, WORD_BYTES);

    int mag_equal = (memcmp(mem_v, mem_r_ref, WORD_BYTES) == 0);

    printf("\n-- Step 5: RAW memory compare (Option B) --\n");
    printf("Result sign bit (FLAG_R_SIGN) = %d\n", sign_v);
    printf("Magnitude mem_v vs mem_r_ref: %s\n",
           mag_equal ? "MATCH" : "MISMATCH");

    if (mag_equal && sign_v == 0) {
        printf("\nFW pipeline result: SIGNATURE VALID (raw compare)\n");
    } else {
        printf("\nFW pipeline result: SIGNATURE INVALID (raw compare)\n");
    }

    /* Also show canonical mod-n v = Rx_Nnorm mod n for sanity */
    BIGNUM *v_bn = BN_new();
    BN_nnmod(v_bn, Rx_Nnorm, n, ctx);
    print_full("v_bn = Rx_Nnorm mod n", v_bn, n, ctx);
    printf("Canonical compare v_bn ?= r: %s\n",
           (BN_cmp(v_bn, r) == 0) ? "EQUAL" : "DIFFERENT");

    return 0;
}
