#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>

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

#define WORD_BYTES 48   /* keep 384-bit width like ECC engine */

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

/* Encode magnitude + explicit sign into mem + g_flags */
static void encode_mont_with_sign(uint8_t mem[WORD_BYTES],
                                  const BIGNUM *mag,
                                  uint32_t sign_mask,
                                  int negative)   /* 1 = negative, 0 = positive */
{
    BIGNUM *tmp = BN_dup(mag);
    if (!tmp) return;
    BN_set_negative(tmp, negative ? 1 : 0);
    encode_signed(mem, tmp, sign_mask);
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

/* Reduce a signed result into the range [-m .. +m] */
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
 * ENGINE OPS
 * ========================================================== */

static int engine_mod_add(uint8_t memR[WORD_BYTES],
                          const uint8_t memA[WORD_BYTES],
                          const uint8_t memB[WORD_BYTES],
                          const MONT_CTX_WR *mc,
                          BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_add(R, A_s, B_s);
    signed_reduce(R, mc->mod, ctx);

    encode_signed(memR, R, FLAG_R_SIGN);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

static int engine_mod_sub(uint8_t memR[WORD_BYTES],
                          const uint8_t memA[WORD_BYTES],
                          const uint8_t memB[WORD_BYTES],
                          const MONT_CTX_WR *mc,
                          BN_CTX *ctx)
{
    BIGNUM *A_s = decode_signed(memA, FLAG_A_SIGN);
    BIGNUM *B_s = decode_signed(memB, FLAG_B_SIGN);
    BIGNUM *R   = BN_new();
    if (!A_s || !B_s || !R) return 0;

    BN_sub(R, A_s, B_s);
    signed_reduce(R, mc->mod, ctx);

    encode_signed(memR, R, FLAG_R_SIGN);

    BN_free(A_s); BN_free(B_s); BN_free(R);
    return 1;
}

/* Mont multiply (inputs & outputs in Mont domain, signed outside) */
static int engine_mont_mul(uint8_t memR[WORD_BYTES],
                           const uint8_t memA[WORD_BYTES],
                           const uint8_t memB[WORD_BYTES],
                           const MONT_CTX_WR *mc,
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
    BN_nnmod(A_mag, A_mag, mc->mod, ctx);
    BN_nnmod(B_mag, B_mag, mc->mod, ctx);

    if (!BN_mod_mul_montgomery(R_mag, A_mag, B_mag, mc->mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed\n");
        return 0;
    }

    if (signR) BN_set_negative(R_mag, 1);

    encode_signed(memR, R_mag, FLAG_R_SIGN);

    BN_free(A_s); BN_free(B_s);
    BN_free(A_mag); BN_free(B_mag); BN_free(R_mag);
    return 1;
}

/* Mont multiply by 1 (still Mont domain) */
static int engine_mont_mul1(uint8_t memR[WORD_BYTES],
                            const uint8_t memA[WORD_BYTES],
                            const MONT_CTX_WR *mc,
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
    BN_nnmod(A_mag, A_mag, mc->mod, ctx);
    BN_one(one);
    BN_to_montgomery(oneM, one, mc->mont, ctx);

    if (!BN_mod_mul_montgomery(R_mag, A_mag, oneM, mc->mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed (mul1)\n");
        return 0;
    }

    if (signA) BN_set_negative(R_mag, 1);

    encode_signed(memR, R_mag, FLAG_R_SIGN);

    BN_free(A_s);
    BN_free(A_mag); BN_free(R_mag);
    BN_free(one); BN_free(oneM);
    return 1;
}

/* Mont EXP: base in Mont domain (signed), exp positive (non-Mont), result in Mont domain */
static int engine_mont_exp(uint8_t memR[WORD_BYTES],
                           const uint8_t memBase[WORD_BYTES],
                           const uint8_t memExp[WORD_BYTES],
                           const MONT_CTX_WR *mc,
                           BN_CTX *ctx)
{
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

    BN_CTX_start(ctx);
    BIGNUM *resM = BN_CTX_get(ctx);
    BIGNUM *one  = BN_CTX_get(ctx);
    if (!one) { BN_CTX_end(ctx); return 0; }

    BN_one(one);
    BN_to_montgomery(resM, one, mc->mont, ctx);  /* resM = Mont(1) */

    int bits = BN_num_bits(E);
    for (int i = bits - 1; i >= 0; --i) {
        BN_mod_mul_montgomery(resM, resM, resM, mc->mont, ctx);
        if (BN_is_bit_set(E, i)) {
            BN_mod_mul_montgomery(resM, resM, B_M, mc->mont, ctx);
        }
    }
    BN_copy(R_M, resM);
    BN_CTX_end(ctx);

    int exp_is_odd = BN_is_odd(E);
    if (signB && exp_is_odd)
        BN_set_negative(R_M, 1);

    encode_signed(memR, R_M, FLAG_R_SIGN);

    BN_free(B_s); BN_free(E_s);
    BN_free(B_M); BN_free(E); BN_free(R_M);
    return 1;
}

/* ============================================================
 * TEST HELPERS
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

/* ============================================================
 * TESTS
 * ========================================================== */

static void test_add_sub(const MONT_CTX_WR *mc, BN_CTX *ctx, int m)
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

        engine_mod_add(memR, memA, memB, mc, ctx);
        BIGNUM *R_bn = decode_signed(memR, FLAG_R_SIGN);
        int r_int = bn_to_int_signed(R_bn);
        int exp   = expected_add(a, b, m);

        /* Build expected BN */
        BIGNUM *exp_bn = BN_new();
        if (exp < 0) {
            BN_set_word(exp_bn, (unsigned)(-exp));
            BN_set_negative(exp_bn, 1);
        } else {
            BN_set_word(exp_bn, (unsigned)exp);
            BN_set_negative(exp_bn, 0);
        }
        signed_reduce(exp_bn, mc->mod, ctx);

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

        engine_mod_sub(memR, memA, memB, mc, ctx);
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
        signed_reduce(exp_bn, mc->mod, ctx);

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

/* Test Mont multiply and mul1 */
static void test_mont_mul(const MONT_CTX_WR *mc, BN_CTX *ctx, int m)
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
            BN_mod(bnA, bnA, mc->mod, ctx);
            BN_mod(bnB, bnB, mc->mod, ctx);

            BN_to_montgomery(A_M, bnA, mc->mont, ctx);
            BN_to_montgomery(B_M, bnB, mc->mont, ctx);

            uint8_t memA[WORD_BYTES] = {0};
            uint8_t memB[WORD_BYTES] = {0};
            uint8_t memR[WORD_BYTES] = {0};

            g_flags = 0;
            encode_mont_with_sign(memA, A_M, FLAG_A_SIGN, signA);
            encode_mont_with_sign(memB, B_M, FLAG_B_SIGN, signB);

            engine_mont_mul(memR, memA, memB, mc, ctx);

            BIGNUM *R_s = decode_signed(memR, FLAG_R_SIGN);

            BN_mod_mul(prod_norm, bnA, bnB, mc->mod, ctx);
            BN_to_montgomery(prod_M, prod_norm, mc->mont, ctx);
            if (signR) BN_set_negative(prod_M, 1);

            char *A_hex = BN_bn2hex(A_M);
            char *B_hex = BN_bn2hex(B_M);
            char *exp_hex = BN_bn2hex(prod_M);
            char *res_hex = BN_bn2hex(R_s);

            printf("\n[MONT_MUL]\n");
            printf("  a            = %d (sign=%d)\n", a, signA);
            printf("  b            = %d (sign=%d)\n", b, signB);
            printf("  A_M (Mont)   = %s0x%s\n",
                   0 ? "-" : "", A_hex);
            printf("  B_M (Mont)   = %s0x%s\n",
                   0 ? "-" : "", B_hex);
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
        BN_mod(bnA, bnA, mc->mod, ctx);
        BN_to_montgomery(A_M, bnA, mc->mont, ctx);

        uint8_t memA[WORD_BYTES] = {0};
        uint8_t memR[WORD_BYTES] = {0};

        g_flags = 0;
        encode_mont_with_sign(memA, A_M, FLAG_A_SIGN, signA);

        engine_mont_mul1(memR, memA, mc, ctx);

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
static void test_mont_exp(const MONT_CTX_WR *mc, BN_CTX *ctx, int m)
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
        BN_mod(bnA, bnA, mc->mod, ctx);
        BN_to_montgomery(A_M, bnA, mc->mont, ctx);

        BN_set_word(exp_bn, (unsigned)e);

        uint8_t memBase[WORD_BYTES] = {0};
        uint8_t memExp [WORD_BYTES] = {0};
        uint8_t memR   [WORD_BYTES] = {0};

        g_flags = 0;
        encode_mont_with_sign(memBase, A_M, FLAG_A_SIGN, signA);
        encode_signed(memExp, exp_bn, FLAG_B_SIGN); /* exponent always positive */

        engine_mont_exp(memR, memBase, memExp, mc, ctx);

        BIGNUM *R_s = decode_signed(memR, FLAG_R_SIGN);

        BN_mod_exp(bnPow, bnA, exp_bn, mc->mod, ctx);
        BN_to_montgomery(Pow_M, bnPow, mc->mont, ctx);

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
 * MAIN
 * ========================================================== */

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }

    /* Small test modulus m = 97 (odd) */
    BIGNUM *mod = BN_new();
    BN_set_word(mod, 97);

    MONT_CTX_WR mc;
    if (!mont_ctx_init(&mc, mod, ctx)) {
        fprintf(stderr, "mont_ctx_init failed\n");
        return 1;
    }

    printf("Testing engine with small modulus m = 97\n");

    test_add_sub(&mc, ctx, 97);
    test_mont_mul(&mc, ctx, 97);
    test_mont_exp(&mc, ctx, 97);

    mont_ctx_free(&mc);
    BN_free(mod);
    BN_CTX_free(ctx);

    return 0;
}
