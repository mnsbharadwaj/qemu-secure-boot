#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
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
    0x96, 0x95, 0xDB, 0x07, 0x23, 0x7F, 0xDF, 0xC7, 0xC5, 0xC7, 0x2C, 0x55, 0x7F, 0xB5, 0xB8, 0x9B, 
    0x5F, 0xC8, 0x0C, 0xF1, 0x22, 0xA6, 0x31, 0x5A, 0x9F, 0x80, 0x97, 0xBC, 0xA3, 0xBE, 0xCD, 0xF2,
    0x72, 0xCF, 0x99, 0xFF, 0x20, 0x41, 0x94, 0x37, 0x38, 0x14, 0xAA, 0x45, 0xAD, 0xE5, 0x75, 0x45,
    0x95, 0xDA, 0x0B, 0xEE, 0x09, 0x85, 0x62, 0x5C, 0xF3, 0x78, 0x61, 0x70, 0x24, 0x00, 0x44, 0x34
};

uint8_t Signature_bytes[] = {
    0x5B, 0xBD, 0x29, 0x46, 0xC5, 0x8E, 0xBF, 0x5C, 0x7D, 0xFE, 0xBD, 0x5C, 0xBE, 0x5A, 0x2D, 0xC0,
    0xF4, 0xE7, 0xA2, 0xA3, 0xB8, 0xD2, 0x63, 0x53, 0xF3, 0xFC, 0x54, 0x58, 0x9D, 0x18, 0x5F, 0xDD,
    0x75, 0xC3, 0x47, 0x21, 0x0D, 0x9B, 0xB2, 0x81, 0x23, 0x41, 0xD3, 0x8E, 0x14, 0xA2, 0x0F, 0x2D, 
    0x90, 0xAD, 0xF5, 0x21, 0x2F, 0x03, 0x17, 0xB2, 0x61, 0x39, 0x35, 0xAC, 0x76, 0x5F, 0x90, 0xF3,
    0x72, 0x56, 0xB6, 0xDC, 0x0B, 0x04, 0x1C, 0x33, 0xE8, 0x65, 0xDE, 0x34, 0x44, 0x21, 0x44, 0xD3,
    0x10, 0xE0, 0xCB, 0x6C, 0x10, 0x55, 0x89, 0xD8, 0x60, 0x63, 0xCD, 0xDB, 0xD8, 0x0A, 0x96, 0x15
};

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("  %s: %s\n", label, hex);
    OPENSSL_free(hex);
}

void print_hex_input(const char* label, const uint8_t* data, size_t len) {
    printf("  %s: ", label);
    for(size_t i=0; i<len; i++) printf("%02X", data[i]);
    printf("\n");
}

int verify_ecdsa_step_by_step(const uint8_t* msg_digest, 
                              const uint8_t* r_bytes, 
                              const uint8_t* s_bytes,
                              const uint8_t* qx_bytes, 
                              const uint8_t* qy_bytes) {
    int ret = 0;
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx); 

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    BIGNUM* order = BN_CTX_get(ctx); 
    EC_GROUP_get_order(group, order, ctx);

    // Load Inputs
    BIGNUM* r = BN_CTX_get(ctx); BN_bin2bn(r_bytes, P384_LEN, r);
    BIGNUM* s = BN_CTX_get(ctx); BN_bin2bn(s_bytes, P384_LEN, s);
    BIGNUM* e = BN_CTX_get(ctx); BN_bin2bn(msg_digest, P384_LEN, e);
    
    // Load PubKey
    BIGNUM* qx = BN_CTX_get(ctx); BN_bin2bn(qx_bytes, P384_LEN, qx);
    BIGNUM* qy = BN_CTX_get(ctx); BN_bin2bn(qy_bytes, P384_LEN, qy);
    EC_POINT* Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, Q, qx, qy, ctx);

    // Setup Montgomery Context and Constants
    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont_ctx, order, ctx);
    BIGNUM* order_2 = BN_CTX_get(ctx); // This is R^2 mod n
    BN_copy(order_2, mont_ctx->RR);

    printf("\n--- STEP 1: index = order - 2 ---\n");
    BIGNUM* index = BN_CTX_get(ctx);
    BIGNUM* two = BN_CTX_get(ctx);
    BN_set_word(two, 2);
    BN_sub(index, order, two);
    print_bn("index (n-2)", index);

    printf("\n--- STEP 2: S_mont = (s * order_2) mod order ---\n");
    // This is Standard -> Mont Domain Conversion
    BIGNUM* S_mont = BN_CTX_get(ctx);
    BN_mod_mul_montgomery(S_mont, s, order_2, mont_ctx, ctx);
    print_bn("S_mont", S_mont);

    printf("\n--- STEP 3: w = mont_exponential(S_mont ^ index) mod order ---\n");
    // We calculate (s^-1) * R using Montgomery Square-and-Multiply
    // Note: Since S_mont is (s*R), (S_mont)^(n-2) in mont domain results in (s^-1)*R
    BIGNUM* w = BN_CTX_get(ctx);
    // Initialize w to '1' in Mont Domain (which is R)
    BN_mod_mul_montgomery(w, BN_value_one(), order_2, mont_ctx, ctx);

    int num_bits = BN_num_bits(index);
    for (int i = num_bits - 1; i >= 0; i--) {
        BN_mod_mul_montgomery(w, w, w, mont_ctx, ctx); // Square
        if (BN_is_bit_set(index, i)) {
            BN_mod_mul_montgomery(w, w, S_mont, mont_ctx, ctx); // Multiply
        }
    }
    print_bn("w (s_inverse in Mont form)", w);

    printf("\n--- STEP 4: z is hashed message in mont domain ---\n");
    // z = (e * order_2) mod order
    BIGNUM* z = BN_CTX_get(ctx);
    BN_mod_mul_montgomery(z, e, order_2, mont_ctx, ctx);
    print_bn("z (hash in Mont form)", z);

    printf("\n--- STEP 5: calculate u1 = (z * w), u2 = (r * w) ---\n");
    
    // u1 calc: z * w = (eR) * (s^-1 R) * R^-1 = e * s^-1 * R
    // This result is u1 * R (u1 in Mont form)
    BIGNUM* u1_mont = BN_CTX_get(ctx);
    BN_mod_mul_montgomery(u1_mont, z, w, mont_ctx, ctx);
    
    // To use with Point Multiplication, we usually need Standard Integer.
    // Convert u1_mont -> u1_std
    BIGNUM* u1 = BN_CTX_get(ctx);
    BN_from_montgomery(u1, u1_mont, mont_ctx, ctx);
    print_bn("u1 (Scalar)", u1);

    // u2 calc: r * w = r * (s^-1 R) * R^-1 = r * s^-1
    // Since 'r' is standard and 'w' is Mont, the result is Standard!
    BIGNUM* u2 = BN_CTX_get(ctx);
    BN_mod_mul_montgomery(u2, r, w, mont_ctx, ctx);
    print_bn("u2 (Scalar)", u2);

    printf("\n--- STEP 6: calculate x1, y1 curve points ---\n");
    // R' = u1*G + u2*Q
    EC_POINT* P1 = EC_POINT_new(group);
    EC_POINT* P2 = EC_POINT_new(group);
    EC_POINT* R_prime = EC_POINT_new(group);

    

[Image of vector addition]


    // P1 = u1 * G
    EC_POINT_mul(group, P1, u1, NULL, NULL, ctx);
    // P2 = u2 * Q
    EC_POINT_mul(group, P2, NULL, Q, u2, ctx);
    // R' = P1 + P2
    EC_POINT_add(group, R_prime, P1, P2, ctx);

    BIGNUM* x1 = BN_CTX_get(ctx);
    BIGNUM* y1 = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates_GFp(group, R_prime, x1, y1, ctx);
    print_bn("x1", x1);
    print_bn("y1", y1);

    printf("\n--- STEP 7: compare the values of r and x ---\n");
    
    // Convert x1 to Mont and back to handle modulo reduction cleanly, 
    // or just use BN_mod (since P-384 coordinates can be >= order)
    BIGNUM* x_final = BN_CTX_get(ctx);
    BN_mod(x_final, x1, order, ctx);
    
    print_bn("x (mod order)", x_final);
    print_bn("r", r);

    if (BN_cmp(x_final, r) == 0) {
        printf("\n>>> MATCH: VALID SIGNATURE <<<\n");
        ret = 1;
    } else {
        printf("\n>>> MISMATCH <<<\n");
    }

    BN_MONT_CTX_free(mont_ctx);
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
    
    printf("=== ECDSA VERIFICATION: EXACT STEPS ===\n");

    uint8_t digest[SHA384_DIGEST_LENGTH];
    SHA384(aMsg_full, sizeof(aMsg_full), digest);
    print_hex_input("SHA-384", digest, SHA384_DIGEST_LENGTH);

    uint8_t qx[P384_LEN], qy[P384_LEN], r[P384_LEN], s[P384_LEN];
    memcpy(qx, Key_bytes, P384_LEN);
    memcpy(qy, Key_bytes + P384_LEN, P384_LEN);
    memcpy(r, Signature_bytes, P384_LEN);
    memcpy(s, Signature_bytes + P384_LEN, P384_LEN);

    verify_ecdsa_step_by_step(digest, r, s, qx, qy);

    ERR_free_strings();
    return 0;
}
