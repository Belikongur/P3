/*
 *  TÖL103M -- Fall 2024
 *
 *  Some testcases for SHA-256 and RSA signatures
 *  needed in the Assignment P3.
 */

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

// LowNet includes.
#include "lownet.h"
#include "serial_io.h"
#include "testcases.h"

#define HASH_SIZE 32  // SHA-256
#define RSA_SIZE 256  // RSA-2048

// Simple test case, a single' 'a' character!
// > echo -n "a" | sha256sum
// ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  -
static char letter_a = 'a';

/*
 *  Test LowNet frame, with incorrect CRC, but we can sign it anyway!
 *
 *  Resulting SHA-256:
 *  4afdb5cf4fc366b493229e05182121342099d80b0651523537834ddba10c7871
 */
static lownet_frame_t testframe_1 = {
    {0x10, 0x4e}, 1, 1,  // magic[2], source, destination
    1,
    7,
    {0, 0},     // proto, length, reserved[2]
    {1, 2, 3},  // payload (rest are zeroes)
    0           // CRC     (in correct)
};

/*
 *  RSA signature of the above testframe:
 *  - extracted from two signature frames
 */
static uint8_t test_signature[RSA_SIZE] = {
    /******************************** first half  ********************************/
    0x60, 0xd5, 0x4d, 0x4e, 0x48, 0xe9, 0xe3, 0xec, 0x46, 0x19, 0x31, 0x12, 0x74, 0x8b, 0x40, 0xeb,
    0xe0, 0xae, 0x97, 0x23, 0x84, 0x68, 0x6d, 0x8a, 0x92, 0x02, 0xc9, 0x58, 0x27, 0x7a, 0x24, 0x4b,
    0x4c, 0x9e, 0x68, 0xef, 0x81, 0xe5, 0x0b, 0x47, 0x7c, 0xa7, 0x63, 0x99, 0x95, 0x18, 0x78, 0xfe,
    0xa9, 0x07, 0x40, 0x1e, 0x0b, 0x22, 0x6a, 0x55, 0x02, 0xd4, 0xb1, 0x63, 0x9a, 0x1f, 0xfc, 0x9e,
    0xd0, 0x9b, 0xb6, 0x05, 0x82, 0x47, 0xf6, 0x49, 0xc4, 0xdf, 0x56, 0x95, 0x6c, 0xbf, 0x95, 0xb6,
    0x07, 0xea, 0x92, 0x0f, 0xe1, 0x9b, 0x72, 0x56, 0xd9, 0x3e, 0x4a, 0xdc, 0x7b, 0xb2, 0xea, 0xd9,
    0xe2, 0x25, 0x38, 0x85, 0x59, 0x3d, 0xf5, 0xef, 0x1a, 0x47, 0x0d, 0xb7, 0xed, 0xea, 0x89, 0xeb,
    0x52, 0x07, 0x17, 0xf0, 0x74, 0xeb, 0x19, 0x50, 0x70, 0x54, 0xfe, 0x39, 0x08, 0xec, 0xc3, 0x9f,
    /*******************************  second half  ********************************/
    0xec, 0x29, 0x93, 0xad, 0x4f, 0xff, 0xa5, 0xc2, 0x0a, 0x7f, 0x6b, 0x98, 0x85, 0xfc, 0xc8, 0x17,
    0xd4, 0x3c, 0xf6, 0x7c, 0x05, 0x9e, 0xc8, 0xa0, 0x18, 0x89, 0xf1, 0x10, 0x6e, 0xeb, 0x76, 0x62,
    0x96, 0x53, 0x70, 0xe4, 0xf8, 0x4b, 0x34, 0x23, 0xc1, 0xfb, 0x48, 0xb5, 0x69, 0xf4, 0x2b, 0x8a,
    0xa5, 0x1f, 0xd7, 0x06, 0xc0, 0x64, 0xcb, 0x82, 0x60, 0x86, 0x56, 0xd6, 0x45, 0x44, 0x0a, 0xa0,
    0x20, 0x65, 0x7a, 0x04, 0x38, 0xf6, 0x4d, 0x00, 0x9a, 0x1c, 0xb3, 0x14, 0x09, 0x17, 0xa9, 0xe4,
    0xf3, 0x65, 0x46, 0xf5, 0xf8, 0x22, 0xcb, 0x9d, 0x02, 0x66, 0x75, 0x7b, 0x5c, 0x90, 0x6b, 0xbb,
    0x23, 0xb5, 0xc9, 0x37, 0x0c, 0x64, 0xf9, 0xb3, 0x5b, 0x69, 0xd6, 0x81, 0xed, 0x7b, 0xdf, 0xfc,
    0xe2, 0x87, 0x7b, 0x42, 0x9f, 0x7c, 0x99, 0x61, 0xf4, 0x46, 0xb3, 0x69, 0xab, 0xb3, 0xe1, 0x64};

/*
 *  The expected output: (see specs!)
 *   - 220 zeroes
 *   -   4 ones
 *   -  32 msg hash, in total 256 octets
 */
static uint8_t test_signature_plain[RSA_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
    0x4a, 0xfd, 0xb5, 0xcf, 0x4f, 0xc3, 0x66, 0xb4, 0x93, 0x22, 0x9e, 0x05, 0x18, 0x21, 0x21, 0x34,
    0x20, 0x99, 0xd8, 0x0b, 0x06, 0x51, 0x52, 0x35, 0x37, 0x83, 0x4d, 0xdb, 0xa1, 0x0c, 0x78, 0x71};

void hash_function(const uint8_t *data, size_t len, uint8_t *hash) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, hash);

    mbedtls_sha256_free(&ctx);
}

void rsa_function(const uint8_t *data, uint8_t *output) {
    const char *pem_key = lownet_get_signing_key();
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if (mbedtls_pk_parse_public_key(&pk, (const uint8_t *)pem_key, strlen(pem_key) + 1)) {
        mbedtls_pk_free(&pk);
        return;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        serial_write_line("KEY ISN'T RSA");
        mbedtls_pk_free(&pk);
        return;
    }

    if (mbedtls_rsa_public(mbedtls_pk_rsa(pk), data, output)) {
        serial_write_line("Error in decryption");
    }
    mbedtls_pk_free(&pk);
}

void sign_command(char *) {
    hash_f *h = hash_function;
    rsa_f *r = rsa_function;
    signature_test(h, r);
}

void print_hash(const uint8_t *hash) {
    char buf[80];
    for (int i = 0; i < HASH_SIZE; i++)
        sprintf(buf + 2 * i, "%02x", hash[i]);
    serial_write_line(buf);
}

void print_rsa(const uint8_t *rsa) {
    char buf[80];

    buf[0] = '\0';

    for (int i = 0; i < RSA_SIZE; i++) {
        sprintf(buf + strlen(buf), "%c%02x", (i % 16) == 0 ? ' ' : ',', rsa[i]);
        if ((i % 16) == 15) {
            serial_write_line(buf);
            buf[0] = '\0';
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
    }
    serial_write_line(buf);
}

/*
 *  Call this from user interface when asked!
 *
 *  - hash_f is user-defined function that computes SHA-256 hash
 *    on given data
 *  - rsa_f is user-defined function that computes RSA-decryption
 *    using the public key of the master node(!)
 */
int signature_test(hash_f *hf, rsa_f *rf) {
    /*
     * Check first SHA-256 with two inputs
     */
    uint8_t hash[HASH_SIZE];

    serial_write_line("SHA-256 on letter a  (=> ca978112ca1bbdcafa... ?)");

    (*hf)((const uint8_t *)&letter_a, 1, hash);
    print_hash((uint8_t *)hash);

    serial_write_line("SHA-256 on test frame, the h_m (=> 4afdb5cf4fc366b4932... ?)");
    (*hf)((const uint8_t *)&testframe_1, sizeof(lownet_frame_t), hash);
    print_hash((uint8_t *)hash);

    /*
     * Then decode signature using the public key
     */
    uint8_t rsa2[RSA_SIZE];

    vTaskDelay(500 / portTICK_PERIOD_MS);

    serial_write_line("Decoding the test signature ... (220 zeroes, 4 ones, and h_m?)");
    (*rf)(test_signature, rsa2);
    print_rsa(rsa2);

    // compare to the expected result
    int err = 0;
    for (int i = 0; i < RSA_SIZE; i++)
        err += rsa2[i] == test_signature_plain[i] ? 0 : 1;
    if (err)
        printf("- in total %d error%s ...!!!\n", err, err == 1 ? "" : "s");
    else
        printf("- Valid signature recovered!\n");

    return err;
}

// /*
//  *  Test LowNet frame, with incorrect CRC, but we can sign it anyway!
//  *
//  *  Resulting SHA-256:
//  *  4afdb5cf4fc366b493229e05182121342099d80b0651523537834ddba10c7871
//  */
// static const lownet_frame_t testframe_1 = {
//     {0x10, 0x4e}, 1, 1,  // magic[2], source, destination
//     1,
//     7,
//     {0, 0},     // proto, length, reserved[2]
//     {1, 2, 3},  // payload (rest are zeroes)
//     0           // CRC     (in correct)
// };
//
// /*
//  *  RSA signature of the above testframe:
//  *  - extracted from two signature frames
//  */
// static uint8_t test_signature[SIGNATURE_SIZE] = {
//     /******************************** first half  ********************************/
//     0x60, 0xd5, 0x4d, 0x4e, 0x48, 0xe9, 0xe3, 0xec, 0x46, 0x19, 0x31, 0x12, 0x74, 0x8b, 0x40, 0xeb,
//     0xe0, 0xae, 0x97, 0x23, 0x84, 0x68, 0x6d, 0x8a, 0x92, 0x02, 0xc9, 0x58, 0x27, 0x7a, 0x24, 0x4b,
//     0x4c, 0x9e, 0x68, 0xef, 0x81, 0xe5, 0x0b, 0x47, 0x7c, 0xa7, 0x63, 0x99, 0x95, 0x18, 0x78, 0xfe,
//     0xa9, 0x07, 0x40, 0x1e, 0x0b, 0x22, 0x6a, 0x55, 0x02, 0xd4, 0xb1, 0x63, 0x9a, 0x1f, 0xfc, 0x9e,
//     0xd0, 0x9b, 0xb6, 0x05, 0x82, 0x47, 0xf6, 0x49, 0xc4, 0xdf, 0x56, 0x95, 0x6c, 0xbf, 0x95, 0xb6,
//     0x07, 0xea, 0x92, 0x0f, 0xe1, 0x9b, 0x72, 0x56, 0xd9, 0x3e, 0x4a, 0xdc, 0x7b, 0xb2, 0xea, 0xd9,
//     0xe2, 0x25, 0x38, 0x85, 0x59, 0x3d, 0xf5, 0xef, 0x1a, 0x47, 0x0d, 0xb7, 0xed, 0xea, 0x89, 0xeb,
//     0x52, 0x07, 0x17, 0xf0, 0x74, 0xeb, 0x19, 0x50, 0x70, 0x54, 0xfe, 0x39, 0x08, 0xec, 0xc3, 0x9f,
//     /*******************************  second half  ********************************/
//     0xec, 0x29, 0x93, 0xad, 0x4f, 0xff, 0xa5, 0xc2, 0x0a, 0x7f, 0x6b, 0x98, 0x85, 0xfc, 0xc8, 0x17,
//     0xd4, 0x3c, 0xf6, 0x7c, 0x05, 0x9e, 0xc8, 0xa0, 0x18, 0x89, 0xf1, 0x10, 0x6e, 0xeb, 0x76, 0x62,
//     0x96, 0x53, 0x70, 0xe4, 0xf8, 0x4b, 0x34, 0x23, 0xc1, 0xfb, 0x48, 0xb5, 0x69, 0xf4, 0x2b, 0x8a,
//     0xa5, 0x1f, 0xd7, 0x06, 0xc0, 0x64, 0xcb, 0x82, 0x60, 0x86, 0x56, 0xd6, 0x45, 0x44, 0x0a, 0xa0,
//     0x20, 0x65, 0x7a, 0x04, 0x38, 0xf6, 0x4d, 0x00, 0x9a, 0x1c, 0xb3, 0x14, 0x09, 0x17, 0xa9, 0xe4,
//     0xf3, 0x65, 0x46, 0xf5, 0xf8, 0x22, 0xcb, 0x9d, 0x02, 0x66, 0x75, 0x7b, 0x5c, 0x90, 0x6b, 0xbb,
//     0x23, 0xb5, 0xc9, 0x37, 0x0c, 0x64, 0xf9, 0xb3, 0x5b, 0x69, 0xd6, 0x81, 0xed, 0x7b, 0xdf, 0xfc,
//     0xe2, 0x87, 0x7b, 0x42, 0x9f, 0x7c, 0x99, 0x61, 0xf4, 0x46, 0xb3, 0x69, 0xab, 0xb3, 0xe1, 0x64};
//
// void sign_triplets() {
//     lownet_frame_t first = {0};
//     lownet_frame_t second = {0};
//
//     memcpy(&first, &testframe_1, 8);
//     memcpy(&second, &testframe_1, 8);
//
//     uint8_t sign1 = (LOWNET_PROTOCOL_COMMAND | 0b10000000);
//     uint8_t sign2 = (LOWNET_PROTOCOL_COMMAND | 0b11000000);
//
//     // Message frame
//     first.protocol = sign1;
//     second.protocol = sign2;
//
//     uint8_t hash_m[HASH_SIZE];
//     hash((uint8_t *)&testframe_1, LOWNET_FRAME_SIZE, hash_m);
//
//     const char *signing_key = lownet_get_signing_key();
//     uint8_t pem[HASH_SIZE];
//     hash((const uint8_t *)signing_key, strlen(signing_key), pem);
//
//     memcpy(first.payload, pem, HASH_SIZE);
//     memcpy(second.payload, pem, HASH_SIZE);
//     memcpy(&first.payload[HASH_SIZE], hash_m, HASH_SIZE);
//     memcpy(&second.payload[HASH_SIZE], hash_m, HASH_SIZE);
//
//     memcpy(&first.payload[2 * HASH_SIZE], test_signature, SIGNATURE_SIZE / 2);
//     memcpy(&second.payload[2 * HASH_SIZE], &test_signature[SIGNATURE_SIZE / 2], SIGNATURE_SIZE / 2);
//     app_frame_dispatch(&testframe_1);
//     app_frame_dispatch(&first);
//     app_frame_dispatch(&second);
// }