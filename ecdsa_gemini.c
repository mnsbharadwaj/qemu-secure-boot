#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> // For NID_secp384r1
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For exit()

#define P384_LEN 48 // 384 bits = 48 bytes

// --- Global Curve Constants (from your prompt) ---
// R2Order is explicitly used for Montgomery conversions - WE WILL NOT USE THIS IN THIS REVISED SCALAR ARITHMETIC
// So this constant is kept for context, but not used in the scalar arithmetic.
const uint8_t R2Order_bytes[P384_LEN] = { 0xD4, 0x0D, 0x49, 0x17, 0x4A, 0xAB, 0x1C, 0xC5, 0xBF, 0x03, 0x06, 0x06, 0xDE, 0x60, 0x9F, 0x43, 0xCC, 0x96, 0x01, 0xF9, 0xF4, 0xA0, 0xE7, 0x92, 0x0C, 0x42, 0xC9, 0x8A, 0xA7, 0x2D, 0x2D, 0x8E, 0x43, 0xBC, 0xF7, 0x15, 0x39, 0x90, 0x00, 0xED, 0x42, 0xA6, 0xFC, 0x1A, 0x99, 0x56, 0x28, 0x11};

const uint8_t GenX_bytes[P384_LEN] = { 0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7};
const uint8_t GenY_bytes[P384_LEN] = { 0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F};

// --- Test Vectors (from your prompt) ---
uint8_t aMsg_full[] =
{
0xE7, 0xFB, 0x79, 0x09, 0x01, 0xEE, 0x53, 0x7D, 0x86, 0xA7, 0xE9, 0xDB, 0x55, 0xA9, 0xBE, 0x8B,
0x12, 0x58, 0x08, 0x6B, 0x1D, 0x11, 0xA1, 0x9C, 0x8B, 0x1B, 0x99, 0x49, 0x78, 0x39, 0xEC, 0x04,
0xF2, 0x6F, 0x25, 0x9A, 0xDA, 0xBA, 0x4E, 0x7F, 0xBC, 0x64, 0xF8, 0x17, 0xC2, 0xD6, 0x01, 0x65,
0x5A, 0x96, 0x63, 0x4C, 0xA3, 0x0A, 0x29, 0x0C, 0x95, 0x53, 0xC4, 0x4F, 0x6E, 0x0F, 0xE1, 0x7E,
0xBE, 0xAC, 0xB1, 0x57, 0x0E, 0x18, 0x21, 0x76, 0xA4, 0xAC, 0x75, 0x46, 0x1E, 0x37, 0xF0, 0x4F,
0x6B, 0x07, 0x59, 0x5A, 0xB8, 0xAA, 0xB0, 0xA4, 0xC7, 0x34, 0xB2, 0xFC, 0x31, 0xF3, 0x2B, 0x32,
0xAB, 0x16, 0x4E, 0xB2, 0x25, 0x6D, 0x6C, 0xB3, 0xF0, 0x1C, 0xF6, 0x54, 0xAE, 0xF0, 0x41, 0x48,
0x4F, 0xF5, 0x43, 0x99, 0x42, 0x8D, 0x95, 0x0D, 0x5E, 0xD7, 0xC5, 0x7B, 0xCC, 0x12, 0x92, 0x9B
};
uint8_t msg_hash_e_bytes[P384_LEN];

uint8_t Key_bytes[] =
{
0x5E, 0xB8, 0x69, 0x6E, 0x47, 0x9F, 0xE9, 0x57, 0xF1, 0xF2, 0xCB, 0xCF, 0xB1, 0x09, 0xA4, 0xD2,
0xEA, 0x0A, 0x58, 0xCE, 0xDB, 0xEB, 0x70, 0xA0, 0x59, 0x7E, 0x5C, 0x21, 0x09, 0x11, 0x01, 0xDD,
0x96, 0x95, 0xDB, 0x07, 0x23, 0x7F, 0xDF, 0xC7, 0xC5, 0xC7, 0x2C, 0x55, 0x7F, 0xB5, 0xB8, 0x9B, // X-coordinate (P384_LEN bytes)
0x5F, 0xC8, 0x0C, 0xF1, 0x22, 0xA6, 0x31, 0x5A, 0x9F, 0x80, 0x97, 0xBC, 0xA3, 0xBE, 0xCD, 0xF2,
0x72, 0xCF, 0x99, 0xFF, 0x20, 0x41, 0x94, 0x37, 0x38, 0x14, 0xAA, 0x45, 0xAD, 0xE5, 0x75, 0x45,
0x95, 0xDA, 0x0B, 0xEE, 0x09, 0x85, 0x62, 0x5C, 0xF3, 0x78, 0x61, 0x70, 0x24, 0x00, 0x44, 0x34  // Y-coordinate (P384_LEN bytes)
};

uint8_t Signature_bytes[] =
{
0x5B, 0xBD, 0x29, 0x46, 0xC5, 0x8E, 0xBF, 0x5C, 0x7D, 0xFE, 0xBD, 0x5C, 0xBE, 0x5A, 0x2D, 0xC0,
0xF4, 0xE7, 0xA2, 0xA3, 0xB8, 0xD2, 0x63, 0x53, 0xF3, 0xFC, 0x54, 0x58, 0x9D, 0x18, 0x5F, 0xDD,
0x75, 0xC3, 0x47, 0x21, 0x0D, 0x9B, 0xB2, 0x81, 0x23, 0x41, 0xD3, 0x8E, 0x14, 0xA2, 0x0F, 0x2D, // R component (P384_LEN bytes)
0x90, 0xAD, 0xF5, 0x21, 0x2F, 0x03, 0x17, 0xB2, 0x61, 0x39, 0x35, 0xAC, 0x76, 0x5F, 0x90, 0xF3,
0x72, 0x56, 0xB6, 0xDC, 0x0B, 0x04, 0x1C, 0x33, 0xE8, 0x65, 0xDE, 0x34, 0x44, 0x21, 0x44, 0xD3,
0x10, 0xE0, 0xCB, 0x6C, 0x10, 0x55, 0x89, 0xD8, 0x60, 0x63, 0xCD, 0xDB, 0xD8, 0x0A, 0x96, 0x15  // S component (P384_LEN bytes)
};

// --- Utility Functions for BIGNUM printing ---

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

void print_point(const char* label, const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* y = BN_CTX_get(ctx);
    if (!x || !y) {
        fprintf(stderr, "Error allocating BIGNUMs for point printing.\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
        fprintf(stderr, "Error getting affine coordinates for point %s.\n", label);
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("%s:\n", label);
    print_bn("  X", x);
    print_bn("  Y", y);
}

// --- REVISED ECDSA Verification Logic (Standard Scalar Arithmetic) ---

int verify_ecdsa_signature_openssl(const uint8_t* message_hash_bytes,
                                   const uint8_t* r_signature_bytes,
                                   const uint8_t* s_signature_bytes,
                                   const uint8_t* public_key_x_bytes,
                                   const uint8_t* public_key_y_bytes) {
    int ret = 0; // Default to failure

    // Initialize OpenSSL objects
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = NULL;
    EC_POINT *G = NULL, *Q = NULL, *R_prime = NULL;
    BIGNUM *n = NULL, *r = NULL, *s = NULL, *e = NULL;
    BIGNUM *s_inv = NULL; // s_inverse in standard domain
    BIGNUM *u1 = NULL, *u2 = NULL; // u1 and u2 in standard domain
    BIGNUM *x_R_prime = NULL;
    BIGNUM *v = NULL; // Final result (x_R_prime mod n) in standard domain

    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        goto err;
    }
    BN_CTX_start(ctx); // Start BN_CTX for temporary BIGNUMs

    // Allocate BIGNUMs
    n = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    s_inv = BN_CTX_get(ctx);
    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    x_R_prime = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);

    if (!n || !r || !s || !e || !s_inv || !u1 || !u2 || !x_R_prime || !v) {
        fprintf(stderr, "BN_CTX_get failed for BIGNUMs\n");
        goto err;
    }

    // Load curve parameters
    group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (!group) {
        fprintf(stderr, "EC_GROUP_new_by_curve_name failed for P-384\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Get the order 'n' of the curve group (scalar modulus)
    if (!EC_GROUP_get_order(group, n, ctx)) {
        fprintf(stderr, "EC_GROUP_get_order failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Load inputs into BIGNUMs
    if (!BN_bin2bn(r_signature_bytes, P384_LEN, r) ||
        !BN_bin2bn(s_signature_bytes, P384_LEN, s) ||
        !BN_bin2bn(message_hash_bytes, P384_LEN, e)) {
        fprintf(stderr, "BN_bin2bn failed for inputs\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    printf("\n--- Starting ECDSA P-384 Signature Verification (OpenSSL - Standard Scalar Arithmetic) ---\n");
    printf("Curve: NIST P-384\n");
    print_bn("Order (n)", n);
    print_bn("Message Hash (e)", e);
    print_bn("Signature r", r);
    print_bn("Signature s", s);
    printf("--------------------------------------------------------------------------------------\n\n");

    // 0. Preliminary checks
    // Check if r and s are within [1, n-1]
    if (BN_is_zero(r) || BN_cmp(r, n) >= 0 ||
        BN_is_zero(s) || BN_cmp(s, n) >= 0) {
        fprintf(stderr, "Verification Failed: Signature components r or s are out of range [1, n-1].\n");
        goto err;
    }

    // Step 1: Calculate s_inverse = s^(-1) mod n
    printf("Step 1: Calculate s_inverse = s^(-1) mod n\n");
    if (!BN_mod_inverse(s_inv, s, n, ctx)) {
        fprintf(stderr, "BN_mod_inverse failed for s\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_bn("  s_inv", s_inv);
    printf("\n");

    // Step 2: u1 = (e * s_inverse) mod n
    printf("Step 2: Calculate u1 = (e * s_inverse) mod n\n");
    if (!BN_mod_mul(u1, e, s_inv, n, ctx)) {
        fprintf(stderr, "BN_mod_mul failed for u1\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_bn("  u1", u1);
    printf("\n");

    // Step 3: u2 = (r * s_inverse) mod n
    printf("Step 3: Calculate u2 = (r * s_inverse) mod n\n");
    if (!BN_mod_mul(u2, r, s_inv, n, ctx)) {
        fprintf(stderr, "BN_mod_mul failed for u2\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_bn("  u2", u2);
    printf("\n");

    // Initialize EC_POINTS
    G = EC_POINT_new(group);
    Q = EC_POINT_new(group);
    R_prime = EC_POINT_new(group);
    if (!G || !Q || !R_prime) {
        fprintf(stderr, "EC_POINT_new failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Set G (generator) from static constants
    BIGNUM *gen_x_bn = BN_CTX_get(ctx);
    BIGNUM *gen_y_bn = BN_CTX_get(ctx);
    if (!gen_x_bn || !gen_y_bn ||
        !BN_bin2bn(GenX_bytes, P384_LEN, gen_x_bn) ||
        !BN_bin2bn(GenY_bytes, P384_LEN, gen_y_bn) ||
        !EC_POINT_set_affine_coordinates_GFp(group, G, gen_x_bn, gen_y_bn, ctx)) {
        fprintf(stderr, "Failed to set generator G\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_point("  Generator G", group, G, ctx);
    printf("\n");

    // Set Q (public key) from input bytes
    BIGNUM *pub_x_bn = BN_CTX_get(ctx);
    BIGNUM *pub_y_bn = BN_CTX_get(ctx);
    if (!pub_x_bn || !pub_y_bn ||
        !BN_bin2bn(public_key_x_bytes, P384_LEN, pub_x_bn) ||
        !BN_bin2bn(public_key_y_bytes, P384_LEN, pub_y_bn) ||
        !EC_POINT_set_affine_coordinates_GFp(group, Q, pub_x_bn, pub_y_bn, ctx)) {
        fprintf(stderr, "Failed to set public key Q\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_point("  Public Key Q", group, Q, ctx);
    printf("\n");

    // Step 4: Calculate R' = u1*G + u2*Q (double point scalar multiplication)
    printf("Step 4: Calculate R' = u1*G + u2*Q\n");
    // EC_POINT_mul(group, R_prime, scalar_G, point_G, scalar_P, point_P, ctx) calculates scalar_G*point_G + scalar_P*point_P
    // Here, scalar_G=u1, point_G=G, scalar_P=u2, point_P=Q
    if (!EC_POINT_mul(group, R_prime, u1, Q, u2, ctx)) {
        fprintf(stderr, "EC_POINT_mul (double scalar multiply) failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_point("  Calculated R'", group, R_prime, ctx);
    printf("\n");

    // Check if R_prime is the point at infinity
    if (EC_POINT_is_at_infinity(group, R_prime)) {
        fprintf(stderr, "Verification Failed: Calculated R' is the point at infinity.\n");
        goto err;
    }

    // Step 5: Get x-coordinate of R' (x1)
    printf("Step 5: Extract x-coordinate of R' (x_R_prime)\n");
    // EC_POINT_get_affine_coordinates_GFp extracts x and y in standard domain
    if (!EC_POINT_get_affine_coordinates_GFp(group, R_prime, x_R_prime, NULL, ctx)) {
        fprintf(stderr, "EC_POINT_get_affine_coordinates_GFp failed for R'\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_bn("  x_R_prime", x_R_prime);
    printf("\n");

    // Step 6: Calculate v = x_R_prime mod n
    printf("Step 6: Calculate v = x_R_prime mod n\n");
    if (!BN_mod(v, x_R_prime, n, ctx)) {
        fprintf(stderr, "BN_mod failed for v\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }
    print_bn("  v", v);
    printf("\n");

    // Step 7: Compare v with r
    printf("Step 7: Compare v with r_signature\n");
    if (BN_cmp(v, r) == 0) {
        printf("Verification SUCCEEDED: v == r\n");
        ret = 1; // Success!
    } else {
        printf("Verification FAILED: v != r\n");
    }

err:
    if (ret == 0) {
        ERR_print_errors_fp(stderr); // Print any OpenSSL errors if verification failed
    }
    // Clean up OpenSSL objects
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    EC_POINT_free(G);
    EC_POINT_free(Q);
    EC_POINT_free(R_prime); // Ensure R_prime is also freed here

    return ret;
}

int main() {
    // Initialize OpenSSL's error reporting
    ERR_load_crypto_strings(); 

    // --- CRITICAL FIX: HASH THE MESSAGE FIRST ---
    // The input 'e' to ECDSA must be the SHA-384 Hash of the message.
    uint8_t digest[SHA384_DIGEST_LENGTH]; // 48 bytes
    
    // Hash the full message (all 128 bytes of aMsg_full)
    SHA384(aMsg_full, sizeof(aMsg_full), digest);

    printf("Calculated SHA-384 Hash of Message:\n");
    for(int i=0; i<SHA384_DIGEST_LENGTH; i++) {
        printf("%02X", digest[i]);
    }
    printf("\n");

    // Prepare public key coordinates
    uint8_t public_key_x_bytes[P384_LEN];
    uint8_t public_key_y_bytes[P384_LEN];
    memcpy(public_key_x_bytes, Key_bytes, P384_LEN);
    memcpy(public_key_y_bytes, Key_bytes + P384_LEN, P384_LEN);

    // Prepare signature components
    uint8_t r_signature_bytes[P384_LEN];
    uint8_t s_signature_bytes[P384_LEN];
    memcpy(r_signature_bytes, Signature_bytes, P384_LEN);
    memcpy(s_signature_bytes, Signature_bytes + P384_LEN, P384_LEN);

    printf("Attempting ECDSA verification...\n");
    
    // Pass the 'digest' (the hash), NOT the raw message
    int result = verify_ecdsa_signature_openssl(
        digest,                // <--- PASS THE HASH HERE
        r_signature_bytes,
        s_signature_bytes,
        public_key_x_bytes,
        public_key_y_bytes
    );

    if (result) {
        printf("\nECDSA Signature Verification: SUCCESS\n");
    } else {
        printf("\nECDSA Signature Verification: FAILED\n");
    }

    // Clean up
    ERR_free_strings();

    return result == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
