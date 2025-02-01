#include "linuxcrypter.h"
#include "crypto_utils.h"
#include <string.h>
#include <stdlib.h>

lc_error_t decrypt_data(EncryptionContext *ctx, DataBuffer *buffer) {
    if (!ctx || !buffer || !buffer->data || (buffer->length % 16 != 0)) {
        return LC_GENERAL_ERROR;
    }
    
    size_t total_blocks = buffer->length / 16;
    uint8_t *in_ptr = buffer->data;
    __m128i prev_cipher = _mm_setzero_si128();  /* For CBC mode */
    __m128i counter = _mm_setzero_si128();      /* For CTR mode */
    
    if (ctx->mode == 1) {
        prev_cipher = _mm_load_si128((const __m128i*)ctx->iv);
    } else if (ctx->mode == 2) {
        counter = _mm_load_si128((const __m128i*)ctx->iv);
    } else {
        return LC_GENERAL_ERROR;
    }
    
    for (size_t i = 0; i < total_blocks; i++) {
        __m128i cipher_block = _mm_loadu_si128((const __m128i*)in_ptr);
        __m128i decrypted;
        
        if (ctx->mode == 1) {
            /* CBC mode */
            decrypted = block_decrypt(cipher_block, &ctx->key_schedule);
            decrypted = _mm_xor_si128(decrypted, prev_cipher);
            prev_cipher = cipher_block;
        } else {  /* CTR mode */
            __m128i keystream = block_encrypt(counter, &ctx->key_schedule);
            decrypted = _mm_xor_si128(cipher_block, keystream);
            uint64_t *ctr_ptr = (uint64_t*)&counter;
            ctr_ptr[0] = ctr_ptr[0] + 1;
        }
        _mm_storeu_si128((__m128i*)in_ptr, decrypted);
        in_ptr += 16;
    }
    
    /* Verify and remove PKCS#7 padding */
    uint8_t *last_block = buffer->data + buffer->length - 16;
    uint8_t pad_len = last_block[15];
    
    /* Check padding validity */
    if (pad_len == 0 || pad_len > 16) {
        memset(buffer->data, 0, buffer->length);
        __asm__ volatile("" : : "r"(buffer->data) : "memory");
        return LC_PADDING_ERROR;
    }
    
    /* Use constant-time comparison for padding verification */
    uint8_t valid = 1;
    for (int i = 16 - pad_len; i < 16; i++) {
        valid &= (last_block[i] == pad_len);
    }
    
    if (!valid) {
        memset(buffer->data, 0, buffer->length);
        __asm__ volatile("" : : "r"(buffer->data) : "memory");
        return LC_PADDING_ERROR;
    }
    
    buffer->length = buffer->length - pad_len;
    return LC_SUCCESS;
}
