#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "linuxcrypter.h"

/*------------------------------------------------------------
    Utility Functions for Block Encryption/Decryption
--------------------------------------------------------------
    These functions process 16-byte blocks using SIMD
    instructions with inline assembly. In our implementation,
    a simple XOR/addition “cipher” is used. In a production
    system, AES-256 (or a similarly secure algorithm) would
    be implemented (possibly via AES-NI).
--------------------------------------------------------------*/

/**
 * block_encrypt
 *
 * Encrypts a 16-byte block using the provided key.
 * The algorithm performs:
 *    temp = plaintext XOR key_block
 *    ciphertext = temp + constant_vector (byte-wise modulo addition)
 *
 * Inline assembly is used to perform SIMD operations.
 *
 * @param block   __m128i plaintext block.
 * @param key     Pointer to key (first 16 bytes used).
 * @return        __m128i encrypted block.
 */
__m128i block_encrypt(__m128i block, const uint8_t *key);

/**
 * block_decrypt
 *
 * Decrypts a 16-byte block using the provided key.
 * This reverses the encryption operation:
 *    temp = ciphertext - constant_vector
 *    plaintext = temp XOR key_block
 *
 * Inline assembly is used to perform SIMD operations.
 *
 * @param block   __m128i ciphertext block.
 * @param key     Pointer to key (first 16 bytes used).
 * @return        __m128i decrypted block.
 */
__m128i block_decrypt(__m128i block, const uint8_t *key);

#endif // CRYPTO_UTILS_H
