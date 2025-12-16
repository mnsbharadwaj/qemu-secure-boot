/*
 * AES-ECB single-shot encrypt/decrypt using LibTomCrypt
 *
 * Build (example):
 *   gcc -O2 -Wall aes_ecb_one_shot.c -ltomcrypt -o aes_ecb_one_shot
 */

#include <stdio.h>
#include <string.h>
#include <tomcrypt.h>

static void dump_hex(const char *label, const unsigned char *buf, unsigned long len)
{
    unsigned long i;
    printf("%s (%lu bytes): ", label, len);
    for (i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

int main(void)
{
    /* 16-byte plaintext (one AES block) */
    const unsigned char pt[16] = {
        0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,
        0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A
    };

    /* AES-128 key (16 bytes). You can also use 24/32 bytes for AES-192/256 */
    const unsigned char key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
    };

    unsigned char ct[16], rt[16];
    symmetric_ECB ecb;
    int err;

    /* Register ciphers (needed in many LibTomCrypt builds) */
    if (register_cipher(&aes_desc) == -1) {
        printf("Error: AES cipher not available (aes_desc not linked/compiled).\n");
        return 1;
    }

    /* Start ECB with AES */
    err = ecb_start(find_cipher("aes"), key, (int)sizeof(key), 0 /*num_rounds=0*/, &ecb);
    if (err != CRYPT_OK) {
        printf("ecb_start failed: %s\n", error_to_string(err));
        return 1;
    }

    /* Single-shot encrypt 1 block */
    err = ecb_encrypt(pt, ct, 16, &ecb);
    if (err != CRYPT_OK) {
        printf("ecb_encrypt failed: %s\n", error_to_string(err));
        ecb_done(&ecb);
        return 1;
    }

    /* Single-shot decrypt 1 block */
    err = ecb_decrypt(ct, rt, 16, &ecb);
    if (err != CRYPT_OK) {
        printf("ecb_decrypt failed: %s\n", error_to_string(err));
        ecb_done(&ecb);
        return 1;
    }

    ecb_done(&ecb);

    dump_hex("PT", pt, 16);
    dump_hex("CT", ct, 16);
    dump_hex("RT", rt, 16);

    if (memcmp(pt, rt, 16) == 0) {
        printf("OK: decrypted text matches plaintext.\n");
        return 0;
    } else {
        printf("FAIL: mismatch.\n");
        return 2;
    }
}
