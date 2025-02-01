#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <wmmintrin.h>  // AES-NI intrinsics

// Number of rounds for AES-256
#define AES_256_ROUNDS 14

/*
 * Structure to hold expanded AES-256 key schedule
 * Contains round keys for both encryption and decryption
 */
typedef struct AESKeySchedule {
    __m128i enc_keys[AES_256_ROUNDS + 1];  // Encryption round keys
    __m128i dec_keys[AES_256_ROUNDS + 1];  // Decryption round keys
    int initialized;
} AESKeySchedule;

/*
 * Function prototypes
 */
int init_aes_key_schedule(AESKeySchedule *schedule, const uint8_t *key);
__m128i block_encrypt(__m128i block, const AESKeySchedule *schedule);
__m128i block_decrypt(__m128i block, const AESKeySchedule *schedule);
void cleanup_key_schedule(AESKeySchedule *schedule);

#endif // CRYPTO_UTILS_H
