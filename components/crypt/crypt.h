#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>

#include "lownet.h"

typedef struct {
    uint8_t zeros[220];
    uint8_t ones[4];
    uint8_t hash[32];
} rsa_decrypted_t;

void crypt_decrypt(const lownet_secure_frame_t* cipher, lownet_secure_frame_t* plain);
void crypt_encrypt(const lownet_secure_frame_t* plain, lownet_secure_frame_t* cipher);

// Usage: crypt_setkey_command(KEY)
// Pre:   KEY is NULL,  0, 1, or a AES key
// Post: If key was NULL encryption has been disabled.  If key was 0
//        or 1 the corresponding predefined key has been set as
//        active.  Otherwise KEY has been set as the active key.
// Note:  If key is shorter than LOWNET_KEY_SIZE_AES it will be padded
//        with zeroes.
void crypt_setkey_command(char* args);

// Usage: crypt_test_command(STR)
// Pre:   STR is a string
// Post:  The STR has been encrypted and then decrypted
//        and the result written to the serial port.
void crypt_test_command(char* str);

// Usage: hash(data, len, hash)
// Pre:
//   - data is a pointer to a constant array of uint8_t (bytes), representing the input data to be hashed.
//   - len is the size of the input data in bytes.
//   - hash is a pointer to an array of uint8_t (bytes) where the resulting SHA-256 hash will be stored.
// Post:
//   - The function computes the SHA-256 hash of the input data, and stores the resulting 32-byte (256-bit) hash value in the provided hash array.
//   - The size of the hash array must be at least 32 bytes to accommodate the full SHA-256 result.
void hash(const uint8_t* data, size_t len, uint8_t* hash);

// Usage: rsa(data, output)
// Pre:
//   - data is a pointer to an array of uint8_t(bytes), representing the encrypted input data to be decrypted.
//   - output is a pointer to an array of uint8_t(bytes) where the decrypted data will be stored.
//   - The data array contains an RSA-encrypted message, and its length must match the key size (e.g., 256 bytes for a 2048-bit RSA key).
// Post:
//   - The function decrypts the RSA-encrypted data using a preconfigured RSA public key.
//   - The decrypted result is stored in the output array.
//   - The size of output must match the expected output length of the decryption process (e.g., 256 bytes for a 2048-bit RSA key).
void rsa(const uint8_t* data, uint8_t* output);

#endif
