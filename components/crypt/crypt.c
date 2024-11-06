#include "crypt.h"

#include <aes/esp_aes.h>
#include <esp_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lownet.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "serial_io.h"

void crypt_decrypt(const lownet_secure_frame_t* cipher, lownet_secure_frame_t* plain) {
    const lownet_key_t* key = lownet_get_key();
    unsigned char ivt[LOWNET_IVT_SIZE];
    memcpy(ivt, &cipher->ivt, LOWNET_IVT_SIZE);

    esp_aes_context ctx;
    esp_aes_init(&ctx);

    if (esp_aes_setkey(&ctx, key->bytes, 256)) {
        ESP_LOGE("DECRYPTION", "setkey unsuccessfull");
        return;
    }

    memcpy(plain, cipher, LOWNET_UNENCRYPTED_SIZE + LOWNET_IVT_SIZE);
    int result = esp_aes_crypt_cbc(
        &ctx,
        ESP_AES_DECRYPT,
        LOWNET_ENCRYPTED_SIZE,
        ivt,
        (uint8_t*)&cipher->protocol,
        (uint8_t*)&plain->protocol);
    esp_aes_free(&ctx);
    if (result) ESP_LOGE("DECRYPTION", "Decryption failed");
}

void crypt_encrypt(const lownet_secure_frame_t* plain, lownet_secure_frame_t* cipher) {
    const lownet_key_t* key = lownet_get_key();
    unsigned char ivt[LOWNET_IVT_SIZE];
    memcpy(ivt, &plain->ivt, LOWNET_IVT_SIZE);

    esp_aes_context ctx;
    esp_aes_init(&ctx);

    if (esp_aes_setkey(&ctx, key->bytes, 256)) {
        ESP_LOGE("ENCRYPTION", "setkey unsuccessfull");
        return;
    }

    memcpy(cipher, plain, LOWNET_UNENCRYPTED_SIZE + LOWNET_IVT_SIZE);
    int result = esp_aes_crypt_cbc(
        &ctx,
        ESP_AES_ENCRYPT,
        LOWNET_ENCRYPTED_SIZE,
        ivt,
        (uint8_t*)&plain->protocol,
        (uint8_t*)&cipher->protocol);
    esp_aes_free(&ctx);
    if (result) ESP_LOGE("ENCRYPTION", "Encryption failed");
}

uint8_t char_to_hex(char c) {
    return (c >= '0' && c <= '9') ? (c - '0') : (c >= 'A' && c <= 'F') ? (c - 'A' + 10)
                                                                       : (c - 'a' + 10);
}

// Usage: crypt_command(KEY)
// Pre:   KEY is a valid AES key or NULL
// Post:  If key == NULL encryption has been disabled
//        Else KEY has been set as the encryption key to use for
//        lownet communication.
void crypt_setkey_command(char* args) {
    if (args == NULL || strlen(args) == 0) {
        lownet_set_key(NULL);
        ESP_LOGI("AES", "Encryption has been disabled");
        return;
    }

    size_t arg_len = strlen(args);
    if (arg_len == 1) {
        lownet_key_t key;
        if (args[0] == '0') {
            key = lownet_keystore_read(0);
        } else if (args[0] == '1') {
            key = lownet_keystore_read(1);
        } else {
            ESP_LOGE("AES", "Invalid predefined key");
            return;
        }

        lownet_set_key(&key);
        ESP_LOGI("AES", "Encryption has been set to predefined key %c", args[0]);
        return;
    } else if (arg_len > 64) {
        ESP_LOGE("AES", "Key too long, max 64 hex digits");
        return;
    }

    for (size_t i = 0; i < arg_len; i++) {
        if (!((args[i] >= '0' && args[i] <= '9') ||
              (args[i] >= 'A' && args[i] <= 'F') ||
              (args[i] >= 'a' && args[i] <= 'f'))) {
            ESP_LOGE("AES", "Invalid AES key: contains non-hex characters");
            return;
        }
    }

    uint8_t key[LOWNET_KEY_SIZE_AES] = {0};
    for (size_t i = 0; i < arg_len / 2; i++) {
        key[i] = ((char_to_hex(args[i * 2]) << 4) | char_to_hex(args[i * 2 + 1]));
    }
    if (arg_len % 2 == 1) key[arg_len / 2] = char_to_hex(args[arg_len - 1]) << 4;

    lownet_key_t lownet_key;
    lownet_key.bytes = key;
    lownet_key.size = LOWNET_KEY_SIZE_AES;
    lownet_set_key(&lownet_key);
    ESP_LOGI("AES", "Encryption key set\n");

    // Debugging
    // printf("\nbytes:%zu, args:%s\n", sizeof(key), args);
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");
}

void print_secure_frame(const lownet_secure_frame_t* frame);
void crypt_test_command(char* str) {
    if (!str)
        return;
    if (!lownet_get_key()) {
        serial_write_line("No encryption key set!");
        return;
    }

    // Encrypts and then decrypts a string, can be used to sanity check your
    // implementation.
    lownet_secure_frame_t plain;
    lownet_secure_frame_t cipher;
    lownet_secure_frame_t back;

    memset(&plain, 0, sizeof(lownet_secure_frame_t));
    memset(&cipher, 0, sizeof(lownet_secure_frame_t));
    memset(&back, 0, sizeof(lownet_secure_frame_t));

    const uint8_t cipher_magic[2] = {0x20, 0x4e};

    memcpy(plain.magic, cipher_magic, sizeof cipher_magic);
    plain.source = lownet_get_device_id();
    plain.destination = 0xFF;
    plain.protocol = LOWNET_PROTOCOL_CHAT;
    plain.length = strlen(str);

    *((uint32_t*)plain.ivt) = 123456789;
    strcpy((char*)plain.payload, str);

    crypt_encrypt(&plain, &cipher);

    if (memcmp(&plain, &cipher, LOWNET_UNENCRYPTED_SIZE) != 0) {
        serial_write_line("Unencrypted part of frame not preserved!");
        return;
    }

    if (memcmp(&plain.ivt, &cipher.ivt, LOWNET_IVT_SIZE) != 0) {
        serial_write_line("IVT not preserved!");
        return;
    }

    crypt_decrypt(&cipher, &back);

    if (memcmp(&plain, &back, sizeof plain) == 0) {
        serial_write_line("Encrypt/Decrypt successful");
        return;
    }

    serial_write_line("Encrypt/Decrypt failed");
    char msg[200];
    snprintf(msg, sizeof msg,
             "Unencrypted content: %s\n"
             "IVT:                 %s\n"
             "Encrypted content:   %s\n",
             memcmp(&plain, &back, LOWNET_UNENCRYPTED_SIZE) == 0 ? "Same" : "Different",
             memcmp(&plain.ivt, &back.ivt, LOWNET_IVT_SIZE) == 0 ? "Same" : "Different",
             memcmp(&plain.protocol, &back.protocol, LOWNET_ENCRYPTED_SIZE) == 0 ? "Same" : "Different");
    serial_write_line(msg);

    // printf("\n--------Payload Before Encryption--------\n");
    // print_secure_frame(&plain);
    // printf("\n");
    //
    // crypt_encrypt(&plain, &cipher);
    // printf("--------Payload After Encryption--------\n");
    // print_secure_frame(&cipher);
    // printf("\n");
    //
    // crypt_decrypt(&cipher, &back);
    // printf("--------Payload After Decryption--------\n");
    // print_secure_frame(&back);
    // printf("\n");
}

/*
 *  SHA256 Hash
 *  computes SHA-256 hash on given data
 */
void hash(const uint8_t* data, size_t len, uint8_t* hash) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, hash);

    mbedtls_sha256_free(&ctx);
}

/*
 *  RSA Decryption
 *  computes RSA-decryption using the public key of the master node(!)
 */
void rsa(const uint8_t* data, uint8_t* output) {
    const char* pem_key = lownet_get_signing_key();
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if (mbedtls_pk_parse_public_key(&pk, (const uint8_t*)pem_key, strlen(pem_key) + 1)) {
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

void print_secure_frame(const lownet_secure_frame_t* frame) {
    for (int i = 0; i < sizeof(lownet_secure_frame_t); i++) {
        uint8_t byte = ((uint8_t*)frame)[i];
        printf("%02x[%c]%c", byte, (byte > 31 && byte < 127) ? byte : ' ', ((i & 0xF) != 0xF) ? ' ' : '\n');
    }
}