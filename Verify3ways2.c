#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

static void print_bn(const char *label, const BIGNUM *x)
{
    char *hex = BN_bn2hex(x);
    printf("%s = 0x%s\n", label, hex);
    OPENSSL_free(hex);
}

/* ----------------------------------------------------
 * Your exact 128-byte message
 * ---------------------------------------------------- */
static const unsigned char message[] = {
    0xE7,0xFB,0x79,0x09,0x01,0xEE,0x53,0x7D,0x86,0xA7,0xE9,0xDB,0x55,0xA9,0xBE,0x8B,
    0x12,0x58,0x08,0x6B,0x1D,0x11,0xA1,0x9C,0x8B,0x1B,0x99,0x49,0x78,0x39,0xEC,0x04,
    0xF2,0x6F,0x25,0x9A,0xDA,0xBA,0x4E,0x7F,0xBC,0x64,0xF8,0x17,0xC2,0xD6,0x01,0x65,
    0x5A,0x96,0x63,0x4C,0xA3,0x0A,00x29,0x0C,0x95,0x53,0xC4,0x4F,0x6E,0x0F,0xE1,0x7E,
    0xBE,0xAC,0xB1,0x57,0x0E,0x18,0x21,0x76,0xA4,0xAC,0x75,0x46,0x1E,0x37,0xF0,0x4F,
    0x6B,0x07,0x59,0x5A,0xB8,0xAA,0xB0,0xA4,0xC7,0x34,0xB2,0xFC,0x31,0xF3,0x2B,0x32,
    0xAB,0x16,0x4E,0xB2,0x25,0x6D,0x6C,0xB3,0xF0,0x1C,0xF6,0x54,0xAE,0xF0,0x41,0x48,
    0x4F,0xF5,0x43,0x99,0x42,0x8D,0x95,0x0D,0x5E,0xD7,0xC5,0x7B,0xCC,0x12,0x92,0x9B
};

/* ----------------------------------------------------
 * Valid Public Key Q (Qx || Qy)
 * ---------------------------------------------------- */
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

/* ----------------------------------------------------
 * Valid Signature (r || s)
 * ---------------------------------------------------- */
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


int main(void)
{
    printf("\n====================================================\n");
    printf("      FULL ECDSA CHECK (OpenSSL | Manual | FW)\n");
    printf("====================================================\n\n");

    BN_CTX *ctx = BN_CTX_new();

    /* Load curve */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    /* Load public key */
    BIGNUM *Qx = BN_bin2bn(Q_bin_valid,      48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin_valid + 48, 48, NULL);

    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, Qx, Qy, ctx);

    /* Load signature */
    BIGNUM *r = BN_bin2bn(sig_bin_valid,      48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin_valid + 48, 48, NULL);

    print_bn("r", r);
    print_bn("s", s);

    /* Hash message */
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(message, sizeof(message), hash);

    BIGNUM *e = BN_bin2bn(hash, SHA384_DIGEST_LENGTH, NULL);
    print_bn("e = SHA-384(message)", e);

    /* Order n and curve prime p */
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_GROUP_get_curve(group, p, a, b, ctx);

    print_bn("Order n", n);
    print_bn("Prime p", p);

    /* ---------------------------------------------
     * 1) OpenSSL ECDSA_do_verify()
     * --------------------------------------------- */
    printf("\n=== 1) OpenSSL verify ===\n");
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_set_public_key(key, Q);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_dup(r), BN_dup(s));

    int ok = ECDSA_do_verify(hash, SHA384_DIGEST_LENGTH, sig, key);
    printf("OpenSSL result: %s\n",
           ok == 1 ? "VALID" : "INVALID");

    /* ---------------------------------------------
     * 2) Manual textbook ECDSA verify
     * --------------------------------------------- */
    printf("\n=== 2) Manual textbook verify ===\n");

    BIGNUM *w_inv = BN_mod_inverse(NULL, s, n, ctx);
    print_bn("w_inv = s^{-1} mod n", w_inv);

    BIGNUM *u1 = BN_new();
    BIGNUM *u2 = BN_new();
    BN_mod_mul(u1, e, w_inv, n, ctx);
    BN_mod_mul(u2, r, w_inv, n, ctx);
    print_bn("u1", u1);
    print_bn("u2", u2);

    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, u1, Q, u2, ctx);

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, ctx);

    print_bn("Rx", Rx);
    print_bn("Ry", Ry);

    BIGNUM *v = BN_new();
    BN_nnmod(v, Rx, n, ctx);
    print_bn("v = Rx mod n", v);

    printf("Manual result: %s\n",
           BN_cmp(v, r) == 0 ? "VALID" : "INVALID");


    /* ---------------------------------------------
     * 3) FW-style custom pipeline
     * --------------------------------------------- */
    printf("\n=== 3) FW-style verification ===\n");

    /* Step A — w = s^(n-2) mod n */
    BIGNUM *exp_n2 = BN_dup(n);
    BN_sub_word(exp_n2, 2);

    BIGNUM *w_fw = BN_new();
    BN_mod_exp(w_fw, s, exp_n2, n, ctx);
    print_bn("w_fw = s^(n-2) mod n", w_fw);

    /* Step B — u1 & u2 */
    BIGNUM *u1_fw = BN_new();
    BIGNUM *u2_fw = BN_new();
    BN_mod_mul(u1_fw, e, w_fw, n, ctx);
    BN_mod_mul(u2_fw, r, w_fw, n, ctx);

    print_bn("u1_fw", u1_fw);
    print_bn("u2_fw", u2_fw);

    /* Step C — scalar multiply in MOD P */
    EC_POINT *Rfw = EC_POINT_new(group);
    EC_POINT_mul(group, Rfw, u1_fw, Q, u2_fw, ctx);

    BIGNUM *Rx_fw = BN_new();
    BIGNUM *Ry_fw = BN_new();
    EC_POINT_get_affine_coordinates(group, Rfw, Rx_fw, Ry_fw, ctx);
    print_bn("Rx_fw (mod P)", Rx_fw);

    /* Step D — FW Montgomery pipeline */
    BN_MONT_CTX *mont_p = BN_MONT_CTX_new();
    BN_MONT_CTX *mont_n = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_p, p, ctx);
    BN_MONT_CTX_set(mont_n, n, ctx);

    printf("\n--- FW Montgomery pipeline ---\n");

    BIGNUM *Rx_Mp = BN_new();
    BIGNUM *Rx_back = BN_new();
    BIGNUM *Rx_Mn = BN_new();
    BIGNUM *Rx_fin = BN_new();

    BN_to_montgomery(Rx_Mp,   Rx_fw, mont_p, ctx);
    print_bn("Rx_Mp", Rx_Mp);

    BN_from_montgomery(Rx_back, Rx_Mp, mont_p, ctx);
    print_bn("Rx_back", Rx_back);

    BN_to_montgomery(Rx_Mn, Rx_back, mont_n, ctx);
    print_bn("Rx_Mn", Rx_Mn);

    BN_from_montgomery(Rx_fin, Rx_Mn, mont_n, ctx);
    print_bn("Rx_fin", Rx_fin);

    /* Step E — final mod n */
    BIGNUM *v_fw = BN_new();
    BN_nnmod(v_fw, Rx_fin, n, ctx);
    print_bn("v_fw", v_fw);

    printf("FW result: %s\n",
           BN_cmp(v_fw, r) == 0 ? "VALID" : "INVALID");

    return 0;
}
