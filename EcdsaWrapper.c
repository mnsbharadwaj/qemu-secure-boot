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
            encode_mont_with_sign(memB, B_M, FLAG_B_SIGN, signB);

            engine_mont_mul(memR, memA, memB, mod, mont, ctx);

            BIGNUM *R_s = decode_signed(memR, FLAG_R_SIGN);

            BN_mod_mul(prod_norm, bnA, bnB, mod, ctx);
            BN_to_montgomery(prod_M, prod_norm, mont, ctx);
            if (signR) BN_set_negative(prod_M, 1);

            char *A_hex = BN_bn2hex(A_M);
            char *B_hex = BN_bn2hex(B_M);
            char *exp_hex = BN_bn2hex(prod_M);
            char *res_hex = BN_bn2hex(R_s);

            printf("\n[MONT_MUL]\n");
            printf("  a            = %d (sign=%d)\n", a, signA);
            printf("  b            = %d (sign=%d)\n", b, signB);
            printf("  A_M (Mont)   = 0x%s\n", A_hex);
            printf("  B_M (Mont)   = 0x%s\n", B_hex);
            printf("  expected(M)  = %s0x%s\n",
                   (signR ? "-" : ""), signR ? exp_hex+1 : exp_hex);
            printf("  result(M)    = %s0x%s\n",
                   BN_is_negative(R_s) ? "-" : "",
                   BN_is_negative(R_s) ? res_hex+1 : res_hex);

            int ok = (BN_cmp(R_s, prod_M) == 0);
            printf("  => %s\n", ok ? "PASS" : "FAIL");

            total_mul++;
            if (ok) pass_mul++;

            OPENSSL_free(A_hex);
            OPENSSL_free(B_hex);
            OPENSSL_free(exp_hex);
            OPENSSL_free(res_hex);

            BN_free(R_s);
            BN_CTX_end(ctx);
        }
    }

    /* Mont mul1 tests */
    for (int i = 0; i < nvals; ++i) {
        int a = vals[i];
        BN_CTX_start(ctx);
        BIGNUM *bnA = BN_CTX_get(ctx);
        BIGNUM *A_M = BN_CTX_get(ctx);
        if (!A_M) { BN_CTX_end(ctx); return; }

        int signA = (a < 0);
        int absA  = signA ? -a : a;
        BN_set_word(bnA, (unsigned)absA);
        BN_mod(bnA, bnA, mod, ctx);
        BN_to_montgomery(A_M, bnA, mont, ctx);

        uint8_t memA[WORD_BYTES] = {0};
        uint8_t memR[WORD_BYTES] = {0};

        g_flags = 0;
        encode_mont_with_sign(memA, A_M, FLAG_A_SIGN, signA);

        engine_mont_mul1(memR, memA, mod, mont, ctx);

        BIGNUM *R_s = decode_signed(memR, FLAG_R_SIGN);
        BIGNUM *exp = BN_dup(A_M);
        if (signA) BN_set_negative(exp, 1);

        char *A_hex = BN_bn2hex(A_M);
        char *exp_hex = BN_bn2hex(exp);
        char *res_hex = BN_bn2hex(R_s);

        printf("\n[MONT_MUL1]\n");
        printf("  a            = %d (sign=%d)\n", a, signA);
        printf("  A_M (Mont)   = 0x%s\n", A_hex);
        printf("  expected(M)  = %s0x%s\n",
               (signA ? "-" : ""), signA ? exp_hex+1 : exp_hex);
        printf("  result(M)    = %s0x%s\n",
               BN_is_negative(R_s) ? "-" : "",
               BN_is_negative(R_s) ? res_hex+1 : res_hex);

        int ok = (BN_cmp(R_s, exp) == 0);
        printf("  => %s\n", ok ? "PASS" : "FAIL");

        total_mul1++;
        if (ok) pass_mul1++;

        OPENSSL_free(A_hex);
        OPENSSL_free(exp_hex);
        OPENSSL_free(res_hex);

        BN_free(R_s);
        BN_free(exp);
        BN_CTX_end(ctx);
    }

    printf("\nMONT_MUL:  %d/%d PASS\n", pass_mul, total_mul);
    printf("MONT_MUL1: %d/%d PASS\n", pass_mul1, total_mul1);
}

/* Test Mont EXP */
static void test_mont_exp(const BIGNUM *mod, BN_MONT_CTX *mont, BN_CTX *ctx, int m)
{
    printf("\n=== TEST MONT EXP (mod %d) ===\n", m);

    struct { int base; int exp; } cases[] = {
        {  3, 4 },
        { -3, 5 },
        { 10, 3 },
        { -5, 2 },
        { -5, 3 },
    };
    int ncases = sizeof(cases)/sizeof(cases[0]);

    int pass = 0;

    for (int i = 0; i < ncases; ++i) {
        int a = cases[i].base;
        int e = cases[i].exp;

        BN_CTX_start(ctx);
        BIGNUM *bnA     = BN_CTX_get(ctx);
        BIGNUM *bnPow   = BN_CTX_get(ctx);
        BIGNUM *A_M     = BN_CTX_get(ctx);
        BIGNUM *Pow_M   = BN_CTX_get(ctx);
        BIGNUM *exp_bn  = BN_CTX_get(ctx);
        if (!exp_bn) { BN_CTX_end(ctx); return; }

        int signA = (a < 0);
        int absA  = signA ? -a : a;

        BN_set_word(bnA, (unsigned)absA);
        BN_mod(bnA, bnA, mod, ctx);
        BN_to_montgomery(A_M, bnA, mont, ctx);

        BN_set_word(exp_bn, (unsigned)e);

        uint8_t memBase[WORD_BYTES] = {0};
        uint8_t memExp [WORD_BYTES] = {0};
        uint8_t memR   [WORD_BYTES] = {0};

        g_flags = 0;
        encode_mont_with_sign(memBase, A_M, FLAG_A_SIGN, signA);
        encode_signed(memExp, exp_bn, FLAG_B_SIGN); /* exponent always positive */

        engine_mont_exp(memR, memBase, memExp, mod, mont, ctx);

        BIGNUM *R_s = decode_signed(memR, FLAG_R_SIGN);

        BN_mod_exp(bnPow, bnA, exp_bn, mod, ctx);
        BN_to_montgomery(Pow_M, bnPow, mont, ctx);

        int exp_is_odd = (e & 1);
        int signR = (signA && exp_is_odd) ? 1 : 0;
        if (signR) BN_set_negative(Pow_M, 1);

        char *A_hex   = BN_bn2hex(A_M);
        char *expHex  = BN_bn2hex(exp_bn);
        char *ref_hex = BN_bn2hex(Pow_M);
        char *res_hex = BN_bn2hex(R_s);

        printf("\n[MONT_EXP]\n");
        printf("  base         = %d (sign=%d)\n", a, signA);
        printf("  exponent     = %d (hex=0x%s)\n", e, expHex);
        printf("  A_M (Mont)   = 0x%s\n", A_hex);
        printf("  expected(M)  = %s0x%s\n",
               signR ? "-" : "",
               signR ? ref_hex+1 : ref_hex);
        printf("  result(M)    = %s0x%s\n",
               BN_is_negative(R_s) ? "-" : "",
               BN_is_negative(R_s) ? res_hex+1 : res_hex);

        int ok = (BN_cmp(R_s, Pow_M) == 0);
        printf("  => %s\n", ok ? "PASS" : "FAIL");

        if (ok) pass++;

        OPENSSL_free(A_hex);
        OPENSSL_free(expHex);
        OPENSSL_free(ref_hex);
        OPENSSL_free(res_hex);

        BN_free(R_s);
        BN_CTX_end(ctx);
    }

    printf("\nMONT_EXP: %d/%d PASS\n", pass, ncases);
}

/* ============================================================
 * P-384 ECDSA TEST VECTORS (VALID)
 * ========================================================== */

static const unsigned char message[] = {
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
 * ECDSA verification: Reference & FW-style engine
 * ========================================================== */

static void test_ecdsa_p384_fw(void)
{
    printf("\n=== ECDSA P-384: Reference and FW-style engine ===\n");

    /* Hash message with SHA-384 */
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);

    /* EC key and group */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (!ec_key) {
        fprintf(stderr, "EC_KEY_new_by_curve_name failed\n");
        return;
    }
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *Qx = BN_bin2bn(Q_bin_valid,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin_valid + 48, 48, NULL);
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);
    EC_KEY_set_public_key(ec_key, Q);

    /* Build ECDSA_SIG from r,s */
    BIGNUM *r = BN_bin2bn(sig_bin_valid,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin_valid + 48, 48, NULL);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);

    /* Reference verification */
    int ok = ECDSA_do_verify(hash, SHA384_DIGEST_LENGTH, sig, ec_key);
    if (ok == 1)
        printf("OpenSSL ECDSA_do_verify: VALID SIGNATURE\n");
    else if (ok == 0)
        printf("OpenSSL ECDSA_do_verify: INVALID SIGNATURE\n");
    else
        printf("OpenSSL ECDSA_do_verify: ERROR\n");

    /* Manual FW-style path using our engine */

    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    /* Reduce e mod n */
    BN_nnmod(e, e, order, ctx);

    /* Setup Montgomery for order n */
    BN_MONT_CTX *mont_n = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_n, order, ctx);

    /* Compute R2_order: R^2 mod n, via BN_mod_mul_montgomery(1,1) trick */
    BIGNUM *R2_n = BN_new();
    BN_zero(R2_n);
    {
        BIGNUM *one = BN_new();
        BIGNUM *oneM = BN_new();
        BN_one(one);
        BN_to_montgomery(oneM, one, mont_n, ctx);
        BN_mod_mul_montgomery(R2_n, oneM, oneM, mont_n, ctx);
        BN_free(one);
        BN_free(oneM);
    }

    printf("\n[FW] order n:\n");
    print_full("order", order, order, ctx);
    print_full("e (reduced)", e, order, ctx);

    /* Step 1: s -> Mont(order) using our wrapper (bn_to_mont_via_engine) */
    BIGNUM *s_M = bn_to_mont_via_engine(s, R2_n, order, mont_n, ctx);
    print_full("[FW] s_M (Mont n via engine)", s_M, order, ctx);

    /* Step 2: exp = n - 2, w_M = s_M^(n-2) in Mont domain via engine_mont_exp */
    BIGNUM *exp = BN_dup(order);
    BN_sub_word(exp, 2);
    BIGNUM *w_M = bn_mont_exp_via_engine(s_M, exp, order, mont_n, ctx);
    print_full("[FW] w_M = s^(n-2) in Mont", w_M, order, ctx);

    /* Step 3: Convert w_M from Mont(order) -> w normal via engine wrapper */
    BIGNUM *w = bn_from_mont_via_engine(w_M, order, mont_n, ctx);
    print_full("[FW] w (normal)", w, order, ctx);

    /* Step 4: u1 = e*w mod n, u2 = r*w mod n using Mont domain + engine_mont_mul */

    /* e -> Mont(order) */
    BIGNUM *e_M = bn_to_mont_via_engine(e, R2_n, order, mont_n, ctx);
    BIGNUM *r_M = bn_to_mont_via_engine(r, R2_n, order, mont_n, ctx);

    print_full("[FW] e_M", e_M, order, ctx);
    print_full("[FW] r_M", r_M, order, ctx);
    print_full("[FW] w_M (reused)", w_M, order, ctx);

    /* u1_M = e_M * w_M in Mont via engine */
    uint8_t mem_eM[WORD_BYTES] = {0};
    uint8_t mem_wM[WORD_BYTES] = {0};
    uint8_t mem_u1M[WORD_BYTES] = {0};
    uint8_t mem_u2M[WORD_BYTES] = {0};

    /* encode e_M, w_M as positive signed Mont values */
    g_flags = 0;
    encode_signed(mem_eM, e_M, FLAG_A_SIGN);
    encode_signed(mem_wM, w_M, FLAG_B_SIGN);
    engine_mont_mul(mem_u1M, mem_eM, mem_wM, order, mont_n, ctx);
    BIGNUM *u1_M = decode_signed(mem_u1M, FLAG_R_SIGN);
    BIGNUM *u1   = bn_from_mont_via_engine(u1_M, order, mont_n, ctx);
    print_full("[FW] u1 (normal)", u1, order, ctx);

    /* u2_M = r_M * w_M */
    g_flags = 0;
    encode_signed(mem_eM, r_M, FLAG_A_SIGN);
    encode_signed(mem_wM, w_M, FLAG_B_SIGN);
    engine_mont_mul(mem_u2M, mem_eM, mem_wM, order, mont_n, ctx);
    BIGNUM *u2_M = decode_signed(mem_u2M, FLAG_R_SIGN);
    BIGNUM *u2   = bn_from_mont_via_engine(u2_M, order, mont_n, ctx);
    print_full("[FW] u2 (normal)", u2, order, ctx);

    /* Step 5: EC double scalar multiply on mod-P:
       R = u1*G + u2*Q (u1,u2 normal scalars)
    */
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    if (EC_POINT_is_at_infinity(group, R)) {
        printf("\n[FW] R is at infinity => INVALID SIGNATURE\n");
    } else {
        BIGNUM *Rx = BN_new();
        BIGNUM *Ry = BN_new();
        EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);

        char *Rx_hex = BN_bn2hex(Rx);
        char *Ry_hex = BN_bn2hex(Ry);
        printf("\n[FW] R.x = %s\n[FW] R.y = %s\n", Rx_hex, Ry_hex);
        OPENSSL_free(Rx_hex);
        OPENSSL_free(Ry_hex);

        /* Step 6: FW style transform:
           - Rx is in normal mod-P already (OpenSSL)
           - "convert from Mont P to normal" is effectively no-op here because
             we only have normal representation, but to mimic FW pipeline we do:
                Rx_norm_P  = Rx (normal)
                Rx_M_P     = toMont_P(Rx_norm_P)
                Rx_back_P  = fromMont_P(Rx_M_P)
           - Then:
                Rx_M_n     = toMont_n(Rx_back_P)
                Rx_back_n  = fromMont_n(Rx_M_n)
         */

        /* Setup mont for prime P as well */
        BIGNUM *prime = BN_new();
        EC_GROUP_get_curve(group, prime, NULL, NULL, ctx);
        BN_MONT_CTX *mont_p = BN_MONT_CTX_new();
        BN_MONT_CTX_set(mont_p, prime, ctx);

        /* Compute R2_p just like R2_n */
        BIGNUM *R2_p = BN_new();
        {
            BIGNUM *one = BN_new();
            BIGNUM *oneM = BN_new();
            BN_one(one);
            BN_to_montgomery(oneM, one, mont_p, ctx);
            BN_mod_mul_montgomery(R2_p, oneM, oneM, mont_p, ctx);
            BN_free(one);
            BN_free(oneM);
        }

        /* P side: Rx -> Mont(P) via our engine wrapper, then back */
        BIGNUM *Rx_M_p   = bn_to_mont_via_engine(Rx, R2_p, prime, mont_p, ctx);
        BIGNUM *Rx_backP = bn_from_mont_via_engine(Rx_M_p, prime, mont_p, ctx);
        print_full("[FW] Rx_backP (after P-Mont round trip)", Rx_backP, prime, ctx);

        /* N side: Rx_backP -> Mont(order) via engine wrapper, then back to normal */
        BIGNUM *Rx_M_n   = bn_to_mont_via_engine(Rx_backP, R2_n, order, mont_n, ctx);
        BIGNUM *Rx_backN = bn_from_mont_via_engine(Rx_M_n, order, mont_n, ctx);
        print_full("[FW] Rx_backN (after N-Mont round trip)", Rx_backN, order, ctx);

        /* Step 7: Compare Rx_backN with r */
        if (BN_cmp(Rx_backN, r) == 0) {
            printf("\n[FW] SIGNATURE VALID (Rx_backN == r)\n");
        } else {
            printf("\n[FW] SIGNATURE INVALID (Rx_backN != r)\n");
        }

        BN_free(Rx); BN_free(Ry);
        BN_free(prime);
        BN_free(R2_p);
        BN_MONT_CTX_free(mont_p);
        BN_free(Rx_M_p); BN_free(Rx_backP);
        BN_free(Rx_M_n); BN_free(Rx_backN);
    }

    /* Cleanup */
    BN_free(order);
    BN_free(R2_n);
    BN_MONT_CTX_free(mont_n);

    BN_free(e);
    BN_free(s_M);
    BN_free(w_M);
    BN_free(w);
    BN_free(e_M);
    BN_free(r_M);
    BN_free(u1_M); BN_free(u2_M);
    BN_free(u1);   BN_free(u2);

    BN_CTX_free(ctx);
    EC_KEY_free(ec_key);
    EC_POINT_free(Q);
    ECDSA_SIG_free(sig);
    BN_free(Qx);
    BN_free(Qy);
}

/* ============================================================
 * MAIN
 * ========================================================== */

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }

    /* ---------- Small modulus tests (m = 97) ---------- */
    BIGNUM *mod = BN_new();
    BN_set_word(mod, 97);

    BN_MONT_CTX *mont97 = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont97, mod, ctx);

    printf("Testing engine with small modulus m = 97\n");

    test_add_sub(mod, ctx, 97);
    test_mont_mul(mod, mont97, ctx, 97);
    test_mont_exp(mod, mont97, ctx, 97);

    BN_MONT_CTX_free(mont97);
    BN_free(mod);

    /* ---------- P-384 ECDSA FW-style test ---------- */
    test_ecdsa_p384_fw();

    BN_CTX_free(ctx);
    return 0;
}
