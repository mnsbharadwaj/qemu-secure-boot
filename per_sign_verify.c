#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <stdio.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

int main() {
    // --- Initialize OpenSSL BN_CTX ---
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // --- Parameters from user ---
    unsigned char message[] = {
    // ... (fill with given bytes)
    };
    size_t message_len = sizeof(message);

    unsigned char Q_bin[96] = {
    // ... (fill with given bytes)
    };

    unsigned char sig_bin[96] = {
    // ... (fill with given bytes)
    };

    // --- Set up EC_GROUP for P-384 ---
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);

    // --- Extract public key Q = (Qx, Qy) ---
    BIGNUM *Qx = BN_bin2bn(Q_bin, 48, NULL);
    BIGNUM *Qy = BN_bin2bn(Q_bin + 48, 48, NULL);

    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, Q, Qx, Qy, ctx);

    print_bn("Qx", Qx);
    print_bn("Qy", Qy);

    // --- Extract signature r, s ---
    BIGNUM *r = BN_bin2bn(sig_bin, 48, NULL);
    BIGNUM *s = BN_bin2bn(sig_bin + 48, 48, NULL);

    print_bn("Signature r", r);
    print_bn("Signature s", s);

    // --- Get curve order n ---
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    print_bn("Curve Order n", n);

    // --- Compute temp = n-2 mod n ---
    BIGNUM *bn_2 = BN_new();
    BN_set_word(bn_2, 2);

    BIGNUM *temp = BN_new();
    BN_sub(temp, n, bn_2);
    BN_mod(temp, temp, n, ctx);

    print_bn("temp = n-2 mod n", temp);

    // --- Compute s_inv = s^temp mod n (custom inverse) ---
    BIGNUM *s_inv = BN_new();
    BN_mod_exp(s_inv, s, temp, n, ctx);

    print_bn("s_inv (custom)", s_inv);

    // --- Hash the message ---
    unsigned char hash[48];
    SHA384(message, message_len, hash);

    BIGNUM *e = BN_bin2bn(hash, 48, NULL);
    print_bn("e (hash)", e);

    // -- Intermediate multiplications (Montgomery/symmetric stylized) --
    // u1 = e * s_inv mod n
    BIGNUM *u1 = BN_new();
    BN_mod_mul(u1, e, s_inv, n, ctx);
    print_bn("u1 = e * s_inv mod n", u1);

    // u2 = r * s_inv mod n
    BIGNUM *u2 = BN_new();
    BN_mod_mul(u2, r, s_inv, n, ctx);
    print_bn("u2 = r * s_inv mod n", u2);

    // --- EC scalar multiplications ---
    EC_POINT *point1 = EC_POINT_new(group);
    EC_POINT_mul(group, point1, u1, NULL, NULL, ctx);
    EC_POINT *point2 = EC_POINT_new(group);
    EC_POINT_mul(group, point2, NULL, Q, u2, ctx);

    EC_POINT *sum = EC_POINT_new(group);
    EC_POINT_add(group, sum, point1, point2, ctx);

    // --- Get x-coordinate (v) ---
    BIGNUM *v = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, sum, v, NULL, ctx);

    print_bn("v (calculated)", v);

    // --- Verify: signature valid if v == r mod n ---
    BIGNUM *vr = BN_new();
    BN_mod(vr, v, n, ctx);
    print_bn("v mod n", vr);

    if (BN_cmp(vr, r) == 0)
        printf("Signature is VALID\n");
    else
        printf("Signature is INVALID\n");

    // --- Free ---
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    /* ... Free other OpenSSL objects ... */

    return 0;
}
