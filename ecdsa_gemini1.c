#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> // For NID_secp384r1
#include <openssl/err.h>
#include <openssl/sha.h>     // For SHA384
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define P384_LEN 48

// --- Test Vectors ---
uint8_t aMsg_full[] = {
    0xE7, 0xFB, 0x79, 0x09, 0x01, 0xEE, 0x53, 0x7D, 0x86, 0xA7, 0xE9, 0xDB, 0x55, 0xA9, 0xBE, 0x8B,
    0x12, 0x58, 0x08, 0x6B, 0x1D, 0x11, 0xA1, 0x9C, 0x8B, 0x1B, 0x99, 0x49, 0x78, 0x39, 0xEC, 0x04,
    0xF2, 0x6F, 0x25, 0x9A, 0xDA, 0xBA, 0x4E, 0x7F, 0xBC, 0x64, 0xF8, 0x17, 0xC2, 0xD6, 0x01, 0x65,
    0x5A, 0x96, 0x63, 0x4C, 0xA3, 0x0A, 0x29, 0x0C, 0x95, 0x53, 0xC4, 0x4F, 0x6E, 0x0F, 0xE1, 0x7E,
    0xBE, 0xAC, 0xB1, 0x57, 0x0E, 0x18, 0x21, 0x76, 0xA4, 0xAC, 0x75, 0x46, 0x1E, 0x37, 0xF0, 0x4F,
    0x6B, 0x07, 0x59, 0x5A, 0xB8, 0xAA, 0xB0, 0xA4, 0xC7, 0x34, 0xB2, 0xFC, 0x31, 0xF3, 0x2B, 0x32,
    0xAB, 0x16, 0x4E, 0xB2, 0x25, 0x6D, 0x6C, 0xB3, 0xF0, 0x1C, 0xF6, 0x54, 0xAE, 0xF0, 0x41, 0x48,
    0x4F, 0xF5, 0x43, 0x99, 0x42, 0x8D, 0x95, 0x0D, 0x5E, 0xD7, 0xC5, 0x7B, 0xCC, 0x12, 0x92, 0x9B
};

uint8_t Key_bytes[] = {
    0x5E, 0xB8, 0x69, 0x6E, 0x47, 0x9F, 0xE9, 0x57, 0xF1, 0xF2, 0xCB, 0xCF, 0xB1, 0x09, 0xA4, 0xD2,
    0xEA, 0x0A, 0x58, 0xCE, 0xDB, 0xEB, 0x70, 0xA0, 0x59, 0x7E, 0x5C, 0x21, 0x09, 0x11, 0x01, 0xDD,
    0x96, 0x95, 0xDB, 0x07, 0x23, 0x7F, 0xDF, 0xC7, 0xC5, 0xC7, 0x2C, 0x55, 0x7F, 0xB5, 0xB8, 0x9B, // X
    0x5F, 0xC8, 0x0C, 0xF1, 0x22, 0xA6, 0x31, 0x5A, 0x9F, 0x80, 0x97, 0xBC, 0xA3, 0xBE, 0xCD, 0xF2,
    0x72, 0xCF, 0x99, 0xFF, 0x20, 0x41, 0x94, 0x37, 0x38, 0x14, 0xAA, 0x45, 0xAD, 0xE5, 0x75, 0x45,
    0x95, 0xDA, 0x0B, 0xEE, 0x09, 0x85, 0x62, 0x5C, 0xF3, 0x78, 0x61, 0x70, 0x24, 0x00, 0x44, 0x34  // Y
};

uint8_t Signature_bytes[] = {
    0x5B, 0xBD, 0x29, 0x46, 0xC5, 0x8E, 0xBF, 0x5C, 0x7D, 0xFE, 0xBD, 0x5C, 0xBE, 0x5A, 0x2D, 0xC0,
    0xF4, 0xE7, 0xA2, 0xA3, 0xB8, 0xD2, 0x63, 0x53, 0xF3, 0xFC, 0x54, 0x58, 0x9D, 0x18, 0x5F, 0xDD,
    0x75, 0xC3, 0x47, 0x21, 0x0D, 0x9B, 0xB2, 0x81, 0x23, 0x41, 0xD3, 0x8E, 0x14, 0xA2, 0x0F, 0x2D, // R
    0x90, 0xAD, 0xF5, 0x21, 0x2F, 0x03, 0x17, 0xB2, 0x61, 0x39, 0x35, 0xAC, 0x76, 0x5F, 0x90, 0xF3,
    0x72, 0x56, 0xB6, 0xDC, 0x0B, 0x04, 0x1C, 0x33, 0xE8, 0x65, 0xDE, 0x34, 0x44, 0x21, 0x44, 0xD3,
    0x10, 0xE0, 0xCB, 0x6C, 0x10, 0x55, 0x89, 0xD8, 0x60, 0x63, 0xCD, 0xDB, 0xD8, 0x0A, 0x96, 0x15  // S
};

// --- Helper Functions ---

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

void print_point(const char* label, const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* y = BN_CTX_get(ctx);
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
        printf("Error getting coordinates for %s\n", label);
        return;
    }
    printf("%s:\n", label);
    print_bn("  X", x);
    print_bn("  Y", y);
}

// --- Detailed Verification Logic ---

int verify_ecdsa_full_trace(const uint8_t* msg_digest, 
                            const uint8_t* r_bytes, 
                            const uint8_t* s_bytes,
                            const uint8_t* qx_bytes, 
                            const uint8_t* qy_bytes) {
    
    int ret = 0;
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx); // Create scope for temp BIGNUMs

    // 1. Initialize Curve and Context
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    BIGNUM* n = BN_CTX_get(ctx); // Curve Order
    EC_GROUP_get_order(group, n, ctx);

    // 2. Load BIGNUMs from bytes
    BIGNUM* r = BN_CTX_get(ctx); BN_bin2bn(r_bytes, P384_LEN, r);
    BIGNUM* s = BN_CTX_get(ctx); BN_bin2bn(s_bytes, P384_LEN, s);
    BIGNUM* e = BN_CTX_get(ctx); BN_bin2bn(msg_digest, P384_LEN, e);
    
    BIGNUM* qx = BN_CTX_get(ctx); BN_bin2bn(qx_bytes, P384_LEN, qx);
    BIGNUM* qy = BN_CTX_get(ctx); BN_bin2bn(qy_bytes, P384_LEN, qy);
    EC_POINT* Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, Q, qx, qy, ctx);

    // -------------------------------------------------------------
    // Step 1: Montgomery Inversion (s^-1 = s^(n-2) mod n)
    // -------------------------------------------------------------
    printf("\n[Step 1] Inversion via Montgomery Exponentiation\n");
    
    // Setup Montgomery Context for Order n
    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_ctx, n, ctx);

    // Calculate Exponent: exp = n - 2
    BIGNUM* exp = BN_CTX_get(ctx);
    BIGNUM* two = BN_CTX_get(ctx);
    BN_set_word(two, 2);
    BN_sub(exp, n, two);
    
    // Calculate s_inv = s^exp mod n
    // BN_mod_exp_mont handles the domain conversion (Standard -> Mont -> Standard) internally
    BIGNUM* s_inv = BN_CTX_get(ctx);
    BN_mod_exp_mont(s_inv, s, exp, n, ctx, mont_ctx);

    print_bn("  Exponent (n-2)", exp);
    print_bn("  s_inverse (s^(n-2))", s_inv);

    // -------------------------------------------------------------
    // Step 2: Scalar Calculation
    // -------------------------------------------------------------
    printf("\n[Step 2] Scalar Calculation\n");
    
    BIGNUM* u1 = BN_CTX_get(ctx);
    BN_mod_mul(u1, e, s_inv, n, ctx); // u1 = e * s_inv
    
    BIGNUM* u2 = BN_CTX_get(ctx);
    BN_mod_mul(u2, r, s_inv, n, ctx); // u2 = r * s_inv

    print_bn("  u1", u1);
    print_bn("  u2", u2);

    // -------------------------------------------------------------
    // Step 3: Point Arithmetic (P1, P2, R')
    // -------------------------------------------------------------
    printf("\n[Step 3] Point Arithmetic\n");

    EC_POINT* P1 = EC_POINT_new(group);
    EC_POINT* P2 = EC_POINT_new(group);
    EC_POINT* R_prime = EC_POINT_new(group);

    // P1 = u1 * G
    EC_POINT_mul(group, P1, u1, NULL, NULL, ctx);
    print_point("  Intermediate Point P1 (u1 * G)", group, P1, ctx);

    // P2 = u2 * Q
    EC_POINT_mul(group, P2, NULL, Q, u2, ctx);
    print_point("  Intermediate Point P2 (u2 * Q)", group, P2, ctx);
    
    

[Image of vector addition]


    // R' = P1 + P2
    EC_POINT_add(group, R_prime, P1, P2, ctx);

    // Check Infinity
    if (EC_POINT_is_at_infinity(group, R_prime)) {
        printf("  Error: R' is at infinity.\n");
        goto cleanup;
    }

    // Get X coordinate (This extracts from Field Element -> Normal Integer)
    BIGNUM* x_coord = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates_GFp(group, R_prime, x_coord, NULL, ctx);
    print_bn("  R'_x (Standard Integer)", x_coord);

    // -------------------------------------------------------------
    // Step 4: Explicit Domain Conversion (Normal -> Mont N -> Normal)
    // -------------------------------------------------------------
    printf("\n[Step 4] Explicit Domain Conversion (Round Trip)\n");
    
    // Convert TO Montgomery Domain (w.r.t Order n)
    // Value = x_coord * R mod n
    BIGNUM* x_in_mont_domain = BN_CTX_get(ctx);
    BN_to_montgomery(x_in_mont_domain, x_coord, mont_ctx, ctx);
    print_bn("  x_coord in Mont N Domain", x_in_mont_domain);

    // Convert FROM Montgomery Domain
    // Value = x_in_mont_domain * R^-1 mod n
    // This effectively performs (x_coord mod n) while returning to normal representation
    BIGNUM* v_recovered = BN_CTX_get(ctx);
    BN_from_montgomery(v_recovered, x_in_mont_domain, mont_ctx, ctx);
    print_bn("  v (Recovered & Reduced mod n)", v_recovered);

    // -------------------------------------------------------------
    // Step 5: Final Comparison
    // -------------------------------------------------------------
    printf("\n[Step 5] Comparison\n");
    print_bn("  Signature r", r);
    print_bn("  Calculated v", v_recovered);

    if (BN_cmp(v_recovered, r) == 0) {
        printf("\n  >>> MATCH (v == r) <<<\n");
        ret = 1;
    } else {
        printf("\n  >>> MISMATCH (v != r) <<<\n");
    }

    BN_MONT_CTX_free(mont_ctx);

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    EC_POINT_free(Q);
    EC_POINT_free(P1);
    EC_POINT_free(P2);
    EC_POINT_free(R_prime);
    return ret;
}

int main() {
    ERR_load_crypto_strings();

    // 1. Calculate Hash
    printf("--- Hashing Message ---\n");
    uint8_t digest[SHA384_DIGEST_LENGTH];
    SHA384(aMsg_full, sizeof(aMsg_full), digest);
    
    printf("SHA-384 Digest: ");
    for(int i=0; i<SHA384_DIGEST_LENGTH; i++) printf("%02X", digest[i]);
    printf("\n");

    // 2. Prepare Inputs
    uint8_t qx[P384_LEN], qy[P384_LEN], r[P384_LEN], s[P384_LEN];
    memcpy(qx, Key_bytes, P384_LEN);
    memcpy(qy, Key_bytes + P384_LEN, P384_LEN);
    memcpy(r, Signature_bytes, P384_LEN);
    memcpy(s, Signature_bytes + P384_LEN, P384_LEN);

    // 3. Run Verification
    int success = verify_ecdsa_full_trace(digest, r, s, qx, qy);

    if (success) printf("\nFinal Verification: SUCCESS\n");
    else printf("\nFinal Verification: FAILED\n");

    ERR_free_strings();
    return 0;
}
