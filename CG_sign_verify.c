#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

// ---- Your data -------------------------------------------------------------

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
static const size_t message_len = sizeof(message);

// P-384 public key Q = (Qx||Qy)
static const unsigned char Q_bin[96] = {
    0x5E,0xB8,0x69,0x6E,0x47,0x9F,0xE9,0x57,0xF1,0xF2,0xCB,0xCF,0xB1,0x09,0xA4,0xD2,
    0xEA,0x0A,0x58,0xCE,0xDB,0xEB,0x70,0xA0,0x59,0x7E,0x5C,0x21,0x09,0x11,0x01,0xDD,
    0x96,0x95,0xDB,0x07,0x23,0x7F,0xDF,0xC7,0xC5,0xC7,0x2C,0x55,0x7F,0xB5,0xB8,0x9B,
    0x5F,0xC8,0x0C,0xF1,0x22,0xA6,0x31,0x5A,0x9F,0x80,0x97,0xBC,0xA3,0xBE,0xCD,0xF2,
    0x72,0xCF,0x99,0xFF,0x20,0x41,0x94,0x37,0x38,0x14,0xAA,0x45,0xAD,0xE5,0x75,0x45,
    0x95,0xDA,0x0B,0xEE,0x09,0x85,0x62,0x5C,0xF3,0x78,0x61,0x70,0x24,0x00,0x44,0x34
};

// Signature (r||s)
static const unsigned char sig_bin[96] = {
    0x5B,0xBD,0x29,0x46,0xC5,0x8E,0xBF,0x5C,0x7D,0xFE,0xBD,0x5C,0xBE,0x5A,0x2D,0xC0,
    0xF4,0xE7,0xA2,0xA3,0xB8,0xD2,0x63,0x53,0xF3,0xFC,0x54,0x58,0x9D,0x18,0x5F,0xDD,
    0x75,0xC3,0x47,0x21,0x0D,0x9B,0xB2,0x81,0x23,0x41,0xD3,0x8E,0x14,0xA2,0x0F,0x2D,
    0x90,0xAD,0xF5,0x21,0x2F,0x03,0x17,0xB2,0x61,0x39,0x35,0xAC,0x76,0x5F,0x90,0xF3,
    0x72,0x56,0xB6,0xDC,0x0B,0x04,0x1C,0x33,0xE8,0x65,0xDE,0x34,0x44,0x21,0x44,0xD3,
    0x10,0xE0,0xCB,0x6C,0x10,0x55,0x89,0xD8,0x60,0x63,0xCD,0xDB,0xD8,0x0A,0x96,0x15
};

// ---- Helpers for symmetric representation ----------------------------------

// Print BIGNUM both in standard [0,mod-1] and symmetric (around 0) form
static void print_bn_symmetric(const char *label,
                               const BIGNUM *x,
                               const BIGNUM *mod,
                               BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *half = BN_CTX_get(ctx);
    BIGNUM *sym = BN_CTX_get(ctx);

    if (!sym) {
        fprintf(stderr, "BN_CTX_get failed\n");
        BN_CTX_end(ctx);
        return;
    }

    // tmp = x mod mod in [0, mod-1]
    BN_nnmod(tmp, x, mod, ctx);

    // half = floor(mod/2)
    BN_rshift1(half, mod);

    // sym = tmp; if tmp > half => sym = tmp - mod (negative)
    BN_copy(sym, tmp);
    if (BN_cmp(tmp, half) > 0) {
        BN_sub(sym, tmp, mod); // now negative
    }

    char *tmp_hex = BN_bn2hex(tmp);
    char *sym_hex = BN_bn2hex(sym);

    printf("%s:\n", label);
    printf("  normal   = 0x%s\n", tmp_hex);
    printf("  symmetric= %s0x%s\n",
           BN_is_negative(sym) ? "-" : "",
           BN_is_negative(sym) ? sym_hex + 1 : sym_hex);

    OPENSSL_free(tmp_hex);
    OPENSSL_free(sym_hex);

    BN_CTX_end(ctx);
}

// Modular add with printing
static void mod_add_sym(BIGNUM *r,
                        const char *label,
                        const BIGNUM *a,
                        const BIGNUM *b,
                        const BIGNUM *mod,
                        BN_CTX *ctx)
{
    printf("\n[MOD ADD] %s\n", label);
    print_bn_symmetric("  a", a, mod, ctx);
    print_bn_symmetric("  b", b, mod, ctx);

    BN_mod_add(r, a, b, mod, ctx);
    print_bn_symmetric("  (a + b) mod n", r, mod, ctx);
}

// Modular sub with printing
static void mod_sub_sym(BIGNUM *r,
                        const char *label,
                        const BIGNUM *a,
                        const BIGNUM *b,
                        const BIGNUM *mod,
                        BN_CTX *ctx)
{
    printf("\n[MOD SUB] %s\n", label);
    print_bn_symmetric("  a", a, mod, ctx);
    print_bn_symmetric("  b", b, mod, ctx);

    BN_mod_sub(r, a, b, mod, ctx);
    print_bn_symmetric("  (a - b) mod n", r, mod, ctx);
}

// Modular mul with printing
static void mod_mul_sym(BIGNUM *r,
                        const char *label,
                        const BIGNUM *a,
                        const BIGNUM *b,
                        const BIGNUM *mod,
                        BN_CTX *ctx)
{
    printf("\n[MOD MUL] %s\n", label);
    print_bn_symmetric("  a", a, mod, ctx);
    print_bn_symmetric("  b", b, mod, ctx);

    BN_mod_mul(r, a, b, mod, ctx);
    print_bn_symmetric("  (a * b) mod n", r, mod, ctx);
}

// Modular exponentiation with printing (square-and-multiply)
static void mod_exp_sym(BIGNUM *r,
                        const char *label,
                        const BIGNUM *base,
                        const BIGNUM *exp,
                        const BIGNUM *mod,
                        BN_CTX *ctx)
{
    printf("\n[MOD EXP] %s\n", label);
    print_bn_symmetric("  base", base, mod, ctx);
    print_bn_symmetric("  exp ", exp,  mod, ctx);

    BN_CTX_start(ctx);
    BIGNUM *result = BN_CTX_get(ctx);
    BIGNUM *b      = BN_CTX_get(ctx);
    if (!b) {
        fprintf(stderr, "BN_CTX_get failed in mod_exp_sym\n");
        BN_CTX_end(ctx);
        return;
    }

    BN_one(result);
    BN_nnmod(b, base, mod, ctx);

    int bits = BN_num_bits(exp);
    for (int i = bits - 1; i >= 0; --i) {
        // result = result^2 mod n
        BN_mod_mul(result, result, result, mod, ctx);
        printf("\n  [EXP] After squaring (bit %d):\n", i);
        print_bn_symmetric("    result", result, mod, ctx);

        if (BN_is_bit_set(exp, i)) {
            // result = result * b mod n
            BN_mod_mul(result, result, b, mod, ctx);
            printf("  [EXP] After multiply (bit %d is 1):\n", i);
            print_bn_symmetric("    result", result, mod, ctx);
        }
    }

    BN_copy(r, result);
    BN_CTX_end(ctx);

    print_bn_symmetric("  (base^exp) mod n", r, mod, ctx);
}

// ---- ECDSA verify (manual) -------------------------------------------------

int main(void)
{
    int ret = 1; // assume failure
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to allocate BN_CTX\n");
        return 1;
    }

    // 1. Set up P-384 group
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (!group) {
        fprintf(stderr, "Failed to create EC_GROUP\n");
        goto cleanup;
    }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    // 2. Get group order n
    BIGNUM *n = BN_new();
    if (!n || EC_GROUP_get_order(group, n, ctx) != 1) {
        fprintf(stderr, "Failed to get group order\n");
        goto cleanup;
    }
    print_bn_symmetric("Order n", n, n, ctx);

    // 3. Build public key Q from Qx||Qy
    BIGNUM *Qx = BN_new();
    BIGNUM *Qy = BN_new();
    EC_POINT *Q = EC_POINT_new(group);
    if (!Qx || !Qy || !Q) {
        fprintf(stderr, "Failed to allocate Q components\n");
        goto cleanup;
    }

    BN_bin2bn(Q_bin, 48, Qx);
    BN_bin2bn(Q_bin + 48, 48, Qy);

    if (EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx) != 1) {
        fprintf(stderr, "Failed to set Q coordinates\n");
        goto cleanup;
    }

    // 4. Parse signature r||s
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BN_bin2bn(sig_bin, 48, r);
    BN_bin2bn(sig_bin + 48, 48, s);

    print_bn_symmetric("Signature r", r, n, ctx);
    print_bn_symmetric("Signature s", s, n, ctx);

    // 4a. Check 1 <= r,s <= n-1
    if (BN_is_zero(r) || BN_is_negative(r) || BN_cmp(r, n) >= 0 ||
        BN_is_zero(s) || BN_is_negative(s) || BN_cmp(s, n) >= 0) {
        fprintf(stderr, "Invalid signature: r or s out of range\n");
        goto cleanup;
    }

    // 5. Hash the message with SHA-384 -> e
    unsigned char digest[SHA384_DIGEST_LENGTH];
    SHA384(message, message_len, digest);

    BIGNUM *e = BN_new();
    BN_bin2bn(digest, sizeof(digest), e); // already 384 bits; no extra truncation
    print_bn_symmetric("Hash e (SHA-384)", e, n, ctx);

    // 6. Compute w = s^(n-2) mod n (Fermat: s^{-1} = s^{n-2} mod n)
    BIGNUM *exp = BN_new();
    BN_copy(exp, n);           // exp = n
    BN_sub_word(exp, 2);       // exp = n - 2
    print_bn_symmetric("Exponent (n-2)", exp, n, ctx);

    BIGNUM *w = BN_new();
    mod_exp_sym(w, "w = s^(n-2) mod n", s, exp, n, ctx);

    // 7. Compute u1 = e * w mod n
    BIGNUM *u1 = BN_new();
    mod_mul_sym(u1, "u1 = e * w mod n", e, w, n, ctx);

    // 8. Compute u2 = r * w mod n
    BIGNUM *u2 = BN_new();
    mod_mul_sym(u2, "u2 = r * w mod n", r, w, n, ctx);

    // 9. Compute R = u1*G + u2*Q
    EC_POINT *R = EC_POINT_new(group);
    if (!R) {
        fprintf(stderr, "Failed to allocate R\n");
        goto cleanup;
    }

    printf("\n[POINT MUL] R = u1*G + u2*Q\n");
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    // 10. Get affine x-coordinate of R and reduce mod n
    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    if (EC_POINT_is_at_infinity(group, R)) {
        fprintf(stderr, "R is point at infinity -> invalid signature\n");
        goto cleanup;
    }

    if (EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx) != 1) {
        fprintf(stderr, "Failed to get affine coords of R\n");
        goto cleanup;
    }

    // For printing, you could also show Rx,Ry mod p, but here we focus on n
    printf("\n[POINT R COORDS]\n");
    char *Rx_hex = BN_bn2hex(Rx);
    char *Ry_hex = BN_bn2hex(Ry);
    printf("  Rx = 0x%s\n", Rx_hex);
    printf("  Ry = 0x%s\n", Ry_hex);
    OPENSSL_free(Rx_hex);
    OPENSSL_free(Ry_hex);

    BIGNUM *v = BN_new(); // v = Rx mod n
    BN_nnmod(v, Rx, n, ctx);
    print_bn_symmetric("v = Rx mod n", v, n, ctx);

    // 11. Check v == r
    if (BN_cmp(v, r) == 0) {
        printf("\n*** Signature is VALID (v == r) ***\n");
        ret = 0;
    } else {
        printf("\n*** Signature is INVALID (v != r) ***\n");
        ret = 1;
    }

cleanup:
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    // free BIGNUMs & points if you want to be very clean; omitted for brevity here.
    return ret;
}
