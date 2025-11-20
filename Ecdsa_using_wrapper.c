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

#define WORD_BYTES 48   /* 384 bits */

/* ============================================================
 * Signed magnitude helpers: values in [-m .. +m]
 * ========================================================== */

/* Decode mem[WORD_BYTES] + sign bit -> signed BIGNUM */
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

/* Encode BIGNUM -> mem[WORD_BYTES] + sign bit */
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

/* For tests: convert small signed int to memory + sign bit */
static void int_to_mem_signed(int val, uint8_t mem[WORD_BYTES], uint32_t sign_mask)
{
    BIGNUM *bn = BN_new();
    if (!bn) return;
    if (val < 0) {
        BN_set_word(bn, (unsigned)(-val));
        BN_set_negative(bn, 1);
    } else {
        BN_set_word(bn, (unsigned)val);
        BN_set_negative(bn, 0);
    }
    encode_signed(mem, bn, sign_mask);
    BN_free(bn);
}

/* For tests: convert signed BN to int (assuming small) */
static int bn_to_int_signed(const BIGNUM *bn)
{
    unsigned long w = BN_get_word(bn);
    if (BN_is_negative(bn))
        return -(int)w;
    return (int)w;
}

/* Reduce signed result into the range [-m .. +m] */
static void signed_reduce(BIGNUM *r, const BIGNUM *mod, BN_CTX *ctx)
{
    (void)ctx;

    BIGNUM *tmp = BN_dup(r);
    BN_set_negative(tmp, 0);

    /* if r > m: r = r - m */
    if (!BN_is_negative(r) && BN_cmp(r, mod) > 0) {
        BN_sub(r, r, mod);
        BN_free(tmp);
        return;
    }

    /* if r < -m: r = r + m */
    if (BN_is_negative(r) && BN_ucmp(tmp, mod) > 0) {
        BN_add(r, r, mod);
    }

    BN_free(tmp);
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
 * ENGINE OPS (modulus passed explicitly)
 * ========================================================== */

/* modular add on [-m..+m] */
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

/* modular sub on [-m..+m] */
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

/* Mont multiply (inputs & outputs in Mont domain, signed outside) */
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

/* Mont multiply by 1 (still Mont domain) */
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

/* Mont EXP: base in Mont domain (signed), exp positive (non-Mont), result in Mont domain */
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

    BIGNUM *B_M   = BN_dup(B_s);  /* Mont base magnitude */
    BIGNUM *E     = BN_dup(E_s);  /* exponent as positive integer */
    BIGNUM *R_M   = BN_new();
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
 * BIGNUM-level helpers using our engine wrappers
 * (for FW-style ECDSA path)
 * ========================================================== */

/* Convert normal BIGNUM x -> Mont(x) using our engine_mont_mul:
 *   x_M = MontMul(x, R2) i.e. x * R^2 mod m -> x*R mod m
 * We work via mem + g_flags.
 */
static BIGNUM *bn_to_mont_via_engine(const BIGNUM *x,
                                     const BIGNUM *R2,
                                     const BIGNUM *mod,
                                     BN_MONT_CTX *mont,
                                     BN_CTX *ctx)
{
    uint8_t memX[WORD_BYTES] = {0};
    uint8_t memR2[WORD_BYTES] = {0};
    uint8_t memR[WORD_BYTES] = {0};

    g_flags = 0;
    /* encode x (assume >=0) */
    encode_signed(memX, x, FLAG_A_SIGN);
    encode_signed(memR2, R2, FLAG_B_SIGN);

    engine_mont_mul(memR, memX, memR2, mod, mont, ctx);

    BIGNUM *X_M = decode_signed(memR, FLAG_R_SIGN);
    return X_M;
}

/* Convert Mont(x) -> normal x using our engine_mont_mul1:
 * In strict math, fromMont(x_M) = MontMul(x_M, 1).
 * We approximate using engine_mont_mul + "1" in normal domain.
 */
static BIGNUM *bn_from_mont_via_engine(const BIGNUM *xM,
                                       const BIGNUM *mod,
                                       BN_MONT_CTX *mont,
                                       BN_CTX *ctx)
{
    uint8_t memX[WORD_BYTES] = {0};
    uint8_t memOne[WORD_BYTES] = {0};
    uint8_t memR[WORD_BYTES] = {0};

    BIGNUM *one = BN_new();
    BN_one(one);

    g_flags = 0;
    encode_signed(memX, xM, FLAG_A_SIGN);
    encode_signed(memOne, one, FLAG_B_SIGN);

    engine_mont_mul(memR, memX, memOne, mod, mont, ctx);

    BIGNUM *res = decode_signed(memR, FLAG_R_SIGN);
    BN_free(one);
    return res;
}

/* Mont exp via engine at BN level: inputs B_M (Mont domain) and exponent E */
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
    encode_signed(memB, B_M, FLAG_A_SIGN);
    encode_signed(memE, E,   FLAG_B_SIGN);

    engine_mont_exp(memR, memB, memE, mod, mont, ctx);

    BIGNUM *R_M = decode_signed(memR, FLAG_R_SIGN);
    return R_M;
}

/* ============================================================
 * SMALL MODULUS TEST SUITE (mod 97)
 * ========================================================== */

static int expected_add(int a, int b, int m)
{
    int r = a + b;
    if (r >  m) r -= m;
    if (r < -m) r += m;
    return r;
}

static int expected_sub(int a, int b, int m)
{
    int r = a - b;
    if (r >  m) r -= m;
    if (r < -m) r += m;
    return r;
}

static void test_add_sub(const BIGNUM *mod, BN_CTX *ctx, int m)
{
    printf("\n=== TEST ADD/SUB (mod %d) ===\n", m);

    struct { int a, b; } cases[] = {
        { 10, 20 },
        { 60, 50 },
        { -30, 40 },
        { -80, -30 },
        { 99, 0 },

        { 50, 20 },
        { 20, 60 },
        { -10, 30 },
        { -60, -50 },
        { 0, -20 },
    };
    int ncases = sizeof(cases)/sizeof(cases[0]);

    int pass_add = 0, pass_sub = 0;

    for (int i = 0; i < ncases; ++i) {
        int a = cases[i].a;
        int b = cases[i].b;

        uint8_t memA[WORD_BYTES] = {0};
        uint8_t memB[WORD_BYTES] = {0};
        uint8_t memR[WORD_BYTES] = {0};

        /* ADD */
        g_flags = 0;
        int_to_mem_signed(a, memA, FLAG_A_SIGN);
        int_to_mem_signed(b, memB, FLAG_B_SIGN);

        engine_mod_add(memR, memA, memB, mod, ctx);
        BIGNUM *R_bn = decode_signed(memR, FLAG_R_SIGN);
        int r_int = bn_to_int_signed(R_bn);
        int exp   = expected_add(a, b, m);

        BIGNUM *exp_bn = BN_new();
        if (exp < 0) {
            BN_set_word(exp_bn, (unsigned)(-exp));
            BN_set_negative(exp_bn, 1);
        } else {
            BN_set_word(exp_bn, (unsigned)exp);
            BN_set_negative(exp_bn, 0);
        }
        signed_reduce(exp_bn, mod, ctx);

        char *exp_hex = BN_bn2hex(exp_bn);
        char *res_hex = BN_bn2hex(R_bn);

        printf("\n[ADD]\n");
        printf("  a        = %d\n", a);
        printf("  b        = %d\n", b);
        printf("  expected = %d (hex=%s%s)\n",
               exp,
               (exp < 0) ? "-" : "",
               (exp < 0) ? exp_hex + 1 : exp_hex);
        printf("  result   = %d (hex=%s%s)\n",
               r_int,
               BN_is_negative(R_bn) ? "-" : "",
               BN_is_negative(R_bn) ? res_hex + 1 : res_hex);

        int ok = (r_int == exp);
        printf("  => %s\n", ok ? "PASS" : "FAIL");

        if (ok) pass_add++;

        OPENSSL_free(exp_hex);
        OPENSSL_free(res_hex);
        BN_free(exp_bn);
        BN_free(R_bn);

        /* SUB */
        g_flags = 0;
        int_to_mem_signed(a, memA, FLAG_A_SIGN);
        int_to_mem_signed(b, memB, FLAG_B_SIGN);

        engine_mod_sub(memR, memA, memB, mod, ctx);
        R_bn = decode_signed(memR, FLAG_R_SIGN);
        r_int = bn_to_int_signed(R_bn);
        exp   = expected_sub(a, b, m);

        exp_bn = BN_new();
        if (exp < 0) {
            BN_set_word(exp_bn, (unsigned)(-exp));
            BN_set_negative(exp_bn, 1);
        } else {
            BN_set_word(exp_bn, (unsigned)exp);
            BN_set_negative(exp_bn, 0);
        }
        signed_reduce(exp_bn, mod, ctx);

        exp_hex = BN_bn2hex(exp_bn);
        res_hex = BN_bn2hex(R_bn);

        printf("\n[SUB]\n");
        printf("  a        = %d\n", a);
        printf("  b        = %d\n", b);
        printf("  expected = %d (hex=%s%s)\n",
               exp,
               (exp < 0) ? "-" : "",
               (exp < 0) ? exp_hex + 1 : exp_hex);
        printf("  result   = %d (hex=%s%s)\n",
               r_int,
               BN_is_negative(R_bn) ? "-" : "",
               BN_is_negative(R_bn) ? res_hex + 1 : res_hex);

        ok = (r_int == exp);
        printf("  => %s\n", ok ? "PASS" : "FAIL");

        if (ok) pass_sub++;

        OPENSSL_free(exp_hex);
        OPENSSL_free(res_hex);
        BN_free(exp_bn);
        BN_free(R_bn);
    }

    printf("\nADD: %d/%d PASS\nSUB: %d/%d PASS\n",
           pass_add, ncases, pass_sub, ncases);
}

/* Encode magnitude + explicit sign into mem + g_flags (for Mont tests) */
static void encode_mont_with_sign(uint8_t mem[WORD_BYTES],
                                  const BIGNUM *mag,
                                  uint32_t sign_mask,
                                  int negative)
{
    BIGNUM *tmp = BN_dup(mag);
    if (!tmp) return;
    BN_set_negative(tmp, negative ? 1 : 0);
    encode_signed(mem, tmp, sign_mask);
    BN_free(tmp);
}

/* Test Mont multiply & mul1 */
static void test_mont_mul(const BIGNUM *mod, BN_MONT_CTX *mont, BN_CTX *ctx, int m)
{
    printf("\n=== TEST MONT MUL/MUL1 (mod %d) ===\n", m);

    int vals[] = { 3, 4, 10, 20, -5, -7 };
    int nvals = sizeof(vals)/sizeof(vals[0]);

    int pass_mul = 0, pass_mul1 = 0;
    int total_mul = 0, total_mul1 = 0;

    for (int i = 0; i < nvals; ++i) {
        for (int j = 0; j < nvals; ++j) {
            int a = vals[i];
            int b = vals[j];

            BN_CTX_start(ctx);
            BIGNUM *bnA = BN_CTX_get(ctx);
            BIGNUM *bnB = BN_CTX_get(ctx);
            BIGNUM *A_M = BN_CTX_get(ctx);
            BIGNUM *B_M = BN_CTX_get(ctx);
            BIGNUM *prod_norm = BN_CTX_get(ctx);
            BIGNUM *prod_M = BN_CTX_get(ctx);
            if (!prod_M) { BN_CTX_end(ctx); return; }

            int signA = (a < 0);
            int signB = (b < 0);
            int signR = signA ^ signB;

            int absA = signA ? -a : a;
            int absB = signB ? -b : b;
            BN_set_word(bnA, (unsigned)absA);
            BN_set_word(bnB, (unsigned)absB);
            BN_mod(bnA, bnA, mod, ctx);
            BN_mod(bnB, bnB, mod, ctx);

            BN_to_montgomery(A_M, bnA, mont, ctx);
            BN_to_montgomery(B_M, bnB, mont, ctx);

            uint8_t memA[WORD_BYTES] = {0};
            uint8_t memB[WORD_BYTES] = {0};
            uint8_t memR[WORD_BYTES] = {0};

            g_flags = 0;
            encode_mont_with_sign(memA, A_M, FLAG_A_SIGN, signA);
            encode_mont_with_sign(memB, B_M, FLAG
