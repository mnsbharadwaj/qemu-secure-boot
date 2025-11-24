#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define P384_LEN 48

// ... [Keep constants aMsg_full, Key_bytes, Signature_bytes from previous code] ...
// (Test vectors omitted for brevity, assume they are present as defined previously)
extern uint8_t aMsg_full[]; 
extern uint8_t Key_bytes[];
extern uint8_t Signature_bytes[];

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

int verify_with_mont_inverse(const uint8_t* msg_digest, 
                             const uint8_t* r_bytes, 
                             const uint8_t* s_bytes,
                             const uint8_t* qx_bytes, 
                             const uint8_t* qy_bytes) {
    
    int ret = 0;
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    BIGNUM* n = BN_CTX_get(ctx);
    EC_GROUP_get_order(group, n, ctx);

    // Inputs
    BIGNUM* r = BN_CTX_get(ctx); BN_bin2bn(r_bytes, P384_LEN, r);
    BIGNUM* s = BN_CTX_get(ctx); BN_bin2bn(s_bytes, P384_LEN, s);
    BIGNUM* e = BN_CTX_get(ctx); BN_bin2bn(msg_digest, P384_LEN, e);
    
    // Public Key
    BIGNUM* qx = BN_CTX_get(ctx); BN_bin2bn(qx_bytes, P384_LEN, qx);
    BIGNUM* qy = BN_CTX_get(ctx); BN_bin2bn(qy_bytes, P384_LEN, qy);
    EC_POINT* Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, Q, qx, qy, ctx);

    // ==============================================================
    // REPLACEMENT: MODULAR INVERSE VIA MONTGOMERY EXPONENTIATION
    // Target: s_inv = s^(n-2) mod n
    // ==============================================================
    printf("\n--- Step 1: Inversion via Montgomery Exponentiation ---\n");

    BIGNUM* s_inv = BN_CTX_get(ctx);
    BIGNUM* exponent = BN_CTX_get(ctx);
    BIGNUM* two = BN_CTX_get(ctx);

    // 1. Create Montgomery Context for Order 'n'
    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_ctx, n, ctx);

    // 2. Calculate Exponent: (n - 2)
    BN_set_word(two, 2);
    BN_sub(exponent, n, two); // exponent = order - 2
    
    // 3. Perform Exponentiation: s_inv = s^exponent mod n
    // BN_mod_exp_mont automatically:
    //    a. Converts 's' to Montgomery Domain (s * R mod n)
    //    b. Performs Square-and-Multiply in Mont Domain
    //    c. Converts result back to Normal Domain
    if (!BN_mod_exp_mont(s_inv, s, exponent, n, ctx, mont_ctx)) {
        fprintf(stderr, "Montgomery Exponentiation Failed\n");
        goto cleanup;
    }

    print_bn("Exponent (n-2)", exponent);
    print_bn("Calculated s_inv (s^(n-2))", s_inv);

    // Verify consistency (Optional check: s * s_inv mod n == 1)
    BIGNUM* check = BN_CTX_get(ctx);
    BN_mod_mul(check, s, s_inv, n, ctx);
    if (BN_is_one(check)) {
        printf("Integrity Check: s * s_inv == 1 mod n [OK]\n");
    }

    // ==============================================================
    // Resume Standard ECDSA Verification
    // ==============================================================

    BIGNUM* u1 = BN_CTX_get(ctx);
    BN_mod_mul(u1, e, s_inv, n, ctx);
    
    BIGNUM* u2 = BN_CTX_get(ctx);
    BN_mod_mul(u2, r, s_inv, n, ctx);

    EC_POINT* R_prime = EC_POINT_new(group);
    EC_POINT_mul(group, R_prime, u1, Q, u2, ctx); // R' = u1*G + u2*Q

    if (EC_POINT_is_at_infinity(group, R_prime)) {
        printf("Error: R' is at infinity.\n"); goto cleanup;
    }

    BIGNUM* x_coord = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates_GFp(group, R_prime, x_coord, NULL, ctx);
    
    BIGNUM* v = BN_CTX_get(ctx);
    BN_mod(v, x_coord, n, ctx);

    if (BN_cmp(v, r) == 0) {
        printf("\nRESULT: MATCH (v == r)\n");
        ret = 1;
    } else {
        printf("\nRESULT: MISMATCH (v != r)\n");
    }

    BN_MONT_CTX_free(mont_ctx);

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    EC_POINT_free(Q);
    EC_POINT_free(R_prime);
    return ret;
}

int main() {
    ERR_load_crypto_strings();

    uint8_t digest[SHA384_DIGEST_LENGTH];
    SHA384(aMsg_full, sizeof(aMsg_full), digest); // Don't forget to Hash!

    uint8_t qx[P384_LEN], qy[P384_LEN], r[P384_LEN], s[P384_LEN];
    memcpy(qx, Key_bytes, P384_LEN);
    memcpy(qy, Key_bytes + P384_LEN, P384_LEN);
    memcpy(r, Signature_bytes, P384_LEN);
    memcpy(s, Signature_bytes + P384_LEN, P384_LEN);

    int success = verify_with_mont_inverse(digest, r, s, qx, qy);

    if (success) printf("\nFinal Status: SUCCESS\n");
    else printf("\nFinal Status: FAILED\n");

    ERR_free_strings();
    return 0;
}
