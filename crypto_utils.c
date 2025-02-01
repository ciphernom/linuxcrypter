/*
 * crypto_utils.c
 * Implementation of AES-256 using AES-NI
 */
#include "crypto_utils.h"
#include <string.h>

// Utility function for AES key expansion
static __m128i aes_256_assist1(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

// Helper for key expansion
static __m128i aes_256_assist2(__m128i temp1) {
    __m128i temp2, temp3;
    temp3 = _mm_aeskeygenassist_si128(temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp3, 0xaa);
    return temp2;
}

int init_aes_key_schedule(AESKeySchedule *schedule, const uint8_t *key) {
    if (!schedule || !key) {
        return -1;
    }

    __m128i temp1, temp2, temp3;
    
    // Load the key into two 128-bit registers
    temp1 = _mm_loadu_si128((__m128i*)key);
    temp3 = _mm_loadu_si128((__m128i*)(key + 16));
    
    // First round key is the first half of the actual key
    schedule->enc_keys[0] = temp1;
    schedule->enc_keys[1] = temp3;
    
    // Generate encryption round keys
    temp2 = aes_256_assist1(temp1, _mm_aeskeygenassist_si128(temp3, 0x01));
    schedule->enc_keys[2] = temp2;
    temp1 = aes_256_assist2(temp2);
    schedule->enc_keys[3] = _mm_xor_si128(temp1, temp3);
    
    temp3 = aes_256_assist1(temp2, _mm_aeskeygenassist_si128(temp1, 0x02));
    schedule->enc_keys[4] = temp3;
    temp2 = aes_256_assist2(temp3);
    schedule->enc_keys[5] = _mm_xor_si128(temp2, temp1);
    
    temp1 = aes_256_assist1(temp3, _mm_aeskeygenassist_si128(temp2, 0x04));
    schedule->enc_keys[6] = temp1;
    temp3 = aes_256_assist2(temp1);
    schedule->enc_keys[7] = _mm_xor_si128(temp3, temp2);
    
    temp2 = aes_256_assist1(temp1, _mm_aeskeygenassist_si128(temp3, 0x08));
    schedule->enc_keys[8] = temp2;
    temp1 = aes_256_assist2(temp2);
    schedule->enc_keys[9] = _mm_xor_si128(temp1, temp3);
    
    temp3 = aes_256_assist1(temp2, _mm_aeskeygenassist_si128(temp1, 0x10));
    schedule->enc_keys[10] = temp3;
    temp2 = aes_256_assist2(temp3);
    schedule->enc_keys[11] = _mm_xor_si128(temp2, temp1);
    
    temp1 = aes_256_assist1(temp3, _mm_aeskeygenassist_si128(temp2, 0x20));
    schedule->enc_keys[12] = temp1;
    temp3 = aes_256_assist2(temp1);
    schedule->enc_keys[13] = _mm_xor_si128(temp3, temp2);
    
    temp2 = aes_256_assist1(temp1, _mm_aeskeygenassist_si128(temp3, 0x40));
    schedule->enc_keys[14] = temp2;
    
    // Generate decryption round keys (inverse of encryption keys)
    schedule->dec_keys[0] = schedule->enc_keys[14];
    for (int i = 1; i < 14; i++) {
        schedule->dec_keys[i] = _mm_aesimc_si128(schedule->enc_keys[14 - i]);
    }
    schedule->dec_keys[14] = schedule->enc_keys[0];
    
    schedule->initialized = 1;
    return 0;
}

__m128i block_encrypt(__m128i block, const AESKeySchedule *schedule) {
    if (!schedule || !schedule->initialized) {
        return _mm_setzero_si128();
    }
    
    __m128i state = _mm_xor_si128(block, schedule->enc_keys[0]);
    
    // AES rounds
    state = _mm_aesenc_si128(state, schedule->enc_keys[1]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[2]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[3]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[4]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[5]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[6]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[7]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[8]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[9]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[10]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[11]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[12]);
    state = _mm_aesenc_si128(state, schedule->enc_keys[13]);
    
    // Final round (different instruction)
    return _mm_aesenclast_si128(state, schedule->enc_keys[14]);
}

__m128i block_decrypt(__m128i block, const AESKeySchedule *schedule) {
    if (!schedule || !schedule->initialized) {
        return _mm_setzero_si128();
    }
    
    __m128i state = _mm_xor_si128(block, schedule->dec_keys[0]);
    
    // AES inverse rounds
    state = _mm_aesdec_si128(state, schedule->dec_keys[1]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[2]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[3]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[4]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[5]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[6]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[7]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[8]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[9]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[10]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[11]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[12]);
    state = _mm_aesdec_si128(state, schedule->dec_keys[13]);
    
    // Final round (different instruction)
    return _mm_aesdeclast_si128(state, schedule->dec_keys[14]);
}

void cleanup_key_schedule(AESKeySchedule *schedule) {
    if (schedule) {
        // Securely zero out all key material
        memset(schedule->enc_keys, 0, sizeof(schedule->enc_keys));
        memset(schedule->dec_keys, 0, sizeof(schedule->dec_keys));
        schedule->initialized = 0;
        // Memory fence to prevent compiler optimization removing the zeroing
        __asm__ volatile("" : : "r"(schedule->enc_keys) : "memory");
        __asm__ volatile("" : : "r"(schedule->dec_keys) : "memory");
    }
}
