/********************************************************************
 *   COMPLETE ECC P-384 VERIFY + SYMMETRIC SIGN-BIT ENCODING
 *   Author: ChatGPT (custom implementation for symmetric pipelines)
 *
 *   Features:
 *   - Sign-bit symmetric encoding in memory (MSB=1 → negative number)
 *   - Accept symmetric or canonical input
 *   - Convert → canonical → compute → symmetric → store
 *   - Full manual ECDSA verify using n-2 exponent for inverse
 *   - Full symmetric/canonical debug prints
 ********************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

/********************************************************************
 *  SIGN-BIT SYMMETRIC ENCODING
 *
 *  Memory format (48 bytes):
 *    MSB bit = 0 → positive canonical number
 *    MSB bit = 1 → NEGATIVE symmetric number x, stored as |x|
 *
 *  Example:
 *      +5  → 00 00 ... 00 05
 *      -5  → 80 00 ... 00 05
 ********************************************************************/

// --------------------------------------------------------------
// Convert 48-byte sign-bit encoded value → BIGNUM (possibly negative)
// --------------------------------------------------------------
BIGNUM *decode_signbit_to_bn(const uint8_t in[48])
{
    int negative = (in[0] & 0x80) != 0;

    uint8_t tmp[48];
    memcpy(tmp, in, 48);

    // Clear the sign-bit from MSB for magnitude
    tmp[0] &= 0x7F;

    BIGNUM *bn = BN_bin2bn(tmp, 48, NULL);
    if (!bn) return NULL;

    if (negative)
        BN_set_negative(bn, 1);

    return bn;
}

// --------------------------------------------------------------
// Encode symmetric BIGNUM → 48 bytes with sign-bit scheme
// --------------------------------------------------------------
void encode_bn_to_signbit(uint8_t out[48], const BIGNUM *bn)
{
    uint8_t tmp[48];
    memset(tmp, 0, 48);

    // get magnitude in big-endian form
    BIGNUM *mag = BN_dup(bn);

    if (BN_is_negative(mag)) {
        BN_set_negative(mag, 0);  // convert -x → x
    }

    BN_bn2binpad(mag, tmp, 48);

    // set negative bit if needed
    if (BN_is_negative(bn))
        tmp[0] |= 0x80;

    memcpy(out, tmp, 48);
    BN_free(mag);
}

/********************************************************************
 *  SYMMETRIC <-> CANONICAL Helpers
 ********************************************************************/

// Convert possibly symmetric → canonical (0 … mod-1)
void to_canonical(BIGNUM *out, const BIGNUM *in, const BIGNUM *mod, BN_CTX *ctx)
{
    BN_nnmod(out, in, mod, ctx);
}

// Convert canonical → symmetric BIGNUM with sign
void to_symmetric(BIGNUM *out, const BIGNUM *can, const BIGNUM *mod, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *half = BN_CTX_get(ctx);
    BIGNUM *tmp  = BN_CTX_get(ctx);

    BN_nnmod(tmp, can, mod, ctx);      // canonical
    BN_rshift1(half, mod);             // mod/2

    if (BN_cmp(tmp, half) > 0) {
        // tmp > mod/2 → represent as negative
        BN_sub(out, tmp, mod);
    } else {
        BN_copy(out, tmp);
    }

    BN_CTX_end(ctx);
}

// Debug printing
void print_bn_symmetric(const char *label, const BIGNUM *bn,
                        const BIGNUM *mod, BN_CTX *ctx)
{
    printf("%s:\n", label);
    BN_CTX_start(ctx);

    BIGNUM *canon = BN_CTX_get(ctx);
    BIGNUM *sym   = BN_CTX_get(ctx);
    BIGNUM *half  = BN_CTX_get(ctx);

    BN_nnmod(canon, bn, mod, ctx);
    BN_rshift1(half, mod);

    if (BN_cmp(canon, half) > 0) {
        BN_sub(sym, canon, mod);
    } else {
        BN_copy(sym, canon);
    }

    char *c_hex = BN_bn2hex(canon);
    char *s_hex = BN_bn2hex(sym);

    printf("  canonical = 0x%s\n", c_hex);
    printf("  symmetric = %s0x%s\n",
           BN_is_negative(sym) ? "-" : "",
           BN_is_negative(sym) ? s_hex + 1 : s_hex);

    OPENSSL_free(c_hex);
    OPENSSL_free(s_hex);

    BN_CTX_end(ctx);
}

/********************************************************************
 *  Modular Arithmetic with Symmetric I/O
 ********************************************************************/

void mod_add_sym(BIGNUM *r, const char *lbl,
                 const BIGNUM *a, const BIGNUM *b,
                 const BIGNUM *mod, BN_CTX *ctx)
{
    printf("\n[MOD ADD] %s\n", lbl);
    BN_CTX_start(ctx);
    BIGNUM *ca = BN_CTX_get(ctx);
    BIGNUM *cb = BN_CTX_get(ctx);

    to_canonical(ca, a, mod, ctx);
    to_canonical(cb, b, mod, ctx);

    print_bn_symmetric("  a", ca, mod, ctx);
    print_bn_symmetric("  b", cb, mod, ctx);

    BN_mod_add(r, ca, cb, mod, ctx);
    print_bn_symmetric("  result", r, mod, ctx);

    BN_CTX_end(ctx);
}

void mod_sub_sym(BIGNUM *r, const char *lbl,
                 const BIGNUM *a, const BIGNUM *b,
                 const BIGNUM *mod, BN_CTX *ctx)
{
    printf("\n[MOD SUB] %s\n", lbl);
    BN_CTX_start(ctx);
    BIGNUM *ca = BN_CTX_get(ctx);
    BIGNUM *cb = BN_CTX_get(ctx);

    to_canonical(ca, a, mod, ctx);
    to_canonical(cb, b, mod, ctx);

    print_bn_symmetric("  a", ca, mod, ctx);
    print_bn_symmetric("  b", cb, mod, ctx);

    BN_mod_sub(r, ca, cb, mod, ctx);
    print_bn_symmetric("  result", r, mod, ctx);

    BN_CTX_end(ctx);
}

void mod_mul_sym(BIGNUM *r, const char *lbl,
                 const BIGNUM *a, const BIGNUM *b,
                 const BIGNUM *mod, BN_CTX *ctx)
{
    printf("\n[MOD MUL] %s\n", lbl);
    BN_CTX_start(ctx);
    BIGNUM *ca = BN_CTX_get(ctx);
    BIGNUM *cb = BN_CTX_get(ctx);

    to_canonical(ca, a, mod, ctx);
    to_canonical(cb, b, mod, ctx);

    print_bn_symmetric("  a", ca, mod, ctx);
    print_bn_symmetric("  b", cb, mod, ctx);

    BN_mod_mul(r, ca, cb, mod, ctx);
    print_bn_symmetric("  result", r, mod, ctx);

    BN_CTX_end(ctx);
}

void mod_exp_sym(BIGNUM *r, const char *lbl,
                 const BIGNUM *base, const BIGNUM *exp,
                 const BIGNUM *mod, BN_CTX *ctx)
{
    printf("\n[MOD EXP] %s\n", lbl);

    BN_CTX_start(ctx);
    BIGNUM *cb = BN_CTX_get(ctx);
    BIGNUM *ce = BN_CTX_get(ctx);
    BIGNUM *result = BN_CTX_get(ctx);
    BIGNUM *bb = BN_CTX_get(ctx);

    to_canonical(cb, base, mod, ctx);
    to_canonical(ce, exp, mod, ctx);

    print_bn_symmetric("  base", cb, mod, ctx);
    print_bn_symmetric("  exp ", ce, mod, ctx);

    BN_one(result);
    BN_copy(bb, cb);

    int bits = BN_num_bits(ce);
    for (int i = bits - 1; i >= 0; i--) {
        BN_mod_mul(result, result, result, mod, ctx);

        if (BN_is_bit_set(ce, i))
            BN_mod_mul(result, result, bb, mod, ctx);
    }

    BN_copy(r, result);
    BN_CTX_end(ctx);

    print_bn_symmetric("  result", r, mod, ctx);
}

/********************************************************************
 *  TEST VECTORS (YOUR INPUT)
 ********************************************************************/

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

/********************************************************************
 *  MAIN — FULL ECDSA VERIFY USING SYMMETRIC SIGN-BIT ENCODING
 ********************************************************************/

int main(void)
{
    BN_CTX *ctx = BN_CTX_new();

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    printf("Order n:\n");
    print_bn_symmetric("n", n, n, ctx);

    /************************************************************
     * Load r, s (signature) using SIGN-BIT encoding pipeline
     ************************************************************/
    uint8_t rbuf[48], sbuf[48];

    memcpy(rbuf, sig_bin, 48);
    memcpy(sbuf, sig_bin + 48, 48);

    BIGNUM *r_in = decode_signbit_to_bn(rbuf);
    BIGNUM *s_in = decode_signbit_to_bn(sbuf);

    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();

    to_canonical(r, r_in, n, ctx);
    to_canonical(s, s_in, n, ctx);

    print_bn_symmetric("r (canonical)", r, n, ctx);
    print_bn_symmetric("s (canonical)", s, n, ctx);

    /************************************************************
     * Hash e = SHA384(message)
     ************************************************************/
    uint8_t hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);

    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_bn_symmetric("e = sha384(message)", e, n, ctx);

    /************************************************************
     * Compute w = s^(n-2) mod n
     ************************************************************/
    BIGNUM *exp = BN_dup(n);
    BN_sub_word(exp, 2);

    BIGNUM *w = BN_new();
    mod_exp_sym(w, "w = s^(n-2) mod n", s, exp, n, ctx);

    /************************************************************
     * u1 = e*w mod n
     * u2 = r*w mod n
     ************************************************************/
    BIGNUM *u1 = BN_new();
    BIGNUM *u2 = BN_new();

    mod_mul_sym(u1, "u1 = e*w", e, w, n, ctx);
    mod_mul_sym(u2, "u2 = r*w", r, w, n, ctx);

    /************************************************************
     * Load public key Q
     ************************************************************/
    BIGNUM *Qx = BN_bin2bn(Q_bin,     48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin+48,  48, NULL);

    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    /************************************************************
     * R = u1*G + u2*Q
     ************************************************************/
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    if (EC_POINT_is_at_infinity(group, R)) {
        printf("Point at infinity → INVALID SIG\n");
        return 1;
    }

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);

    char *rx_hex = BN_bn2hex(Rx);
    char *ry_hex = BN_bn2hex(Ry);
    printf("\nR.x = %s\nR.y = %s\n", rx_hex, ry_hex);
    OPENSSL_free(rx_hex);
    OPENSSL_free(ry_hex);

    /************************************************************
     * v = Rx mod n
     ************************************************************/
    BIGNUM *v = BN_new();
    BN_nnmod(v, Rx, n, ctx);

    print_bn_symmetric("v = Rx mod n", v, n, ctx);

    /************************************************************
     * Check v == r
     ************************************************************/
    if (BN_cmp(v, r) == 0)
        printf("\n✔ SIGNATURE VALID\n");
    else
        printf("\n✘ SIGNATURE INVALID\n");

    /************************************************************
     * Show symmetric ENCODING of final v written to memory
     ************************************************************/
    uint8_t memout[48];
    BIGNUM *v_sym = BN_new();
    to_symmetric(v_sym, v, n, ctx);
    encode_bn_to_signbit(memout, v_sym);

    printf("\nSymmetric sign-bit encoded v (48 bytes):\n");
    for (int i=0;i<48;i++) printf("%02X", memout[i]);
    printf("\n");

    return 0;
}
