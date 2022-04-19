/**
 * @file AEAD.h
 * @author Spartans
 * @brief Bootloader symmetric encryption implementation.
 * @date 2022
 */

#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>

#include "gcm.h"

#define KEY_LEN 16
#define IV_LEN 12
#define TAG_LEN 16

/**
 * @brief Verifies that two uint8_t[] arrays are equal to the first `len` bytes.
 * 
 * @param a   [in] First  array to compare
 * @param b   [in] Second array to compare
 * @param len [in] Size of array to compare
 * @return 1 on success, 0 if any difference
 */
int is_equal(const uint8_t *a, const uint8_t *b, const size_t len);

/**
 * @brief Decapsulates an AEAD package, verifying authorization.
 * 
 * @param pt       Output buffer
 * @param ct       Input buffer
 * @param ct_len   Length of data
 * @param aad      Additional authenticated data buffer
 * @param aad_len  Length of additional authenticated data
 * @param key      Decryption key buffer
 * @param iv       Nonce buffer
 * @param tag      Authentication tag buffer
 * 
 * @return 0 on success, GCM_AUTH_FAILURE otherwise
 */
int aead_dec(   uint8_t *pt,
                const uint8_t *ct,
                const size_t ct_len,
                const uint8_t *aad,
                const size_t aad_len,
                const uint8_t *key,
                const uint8_t *iv,
                const uint8_t *tag
            );

/**
 * @brief Verifies message authorization and integrity.
 * 
 * @param ct       Input buffer
 * @param ct_len   Length of data
 * @param aad      Additional authenticated data buffer
 * @param aad_len  Length of additional authenticated data
 * @param key      Decryption key buffer
 * @param iv       Nonce buffer
 * @param tag      Authentication tag buffer
 * 
 * @return 0 on success, GCM_AUTH_FAILURE otherwise
 */
int check_sig(  const uint8_t *ct,
                const size_t ct_len,
                const uint8_t *aad,
                const size_t aad_len,
                const uint8_t *key,
                const uint8_t *iv,
                const uint8_t *tag
            );

/**
 * @brief Decrypts data for readback access
 * 
 * @param ct       Input buffer
 * @param ct_len   Length of data
 * @param key      Decryption key buffer
 * @param iv       Nonce buffer
 */
void readback_dec(  const uint8_t *ct,
                    const size_t ct_len,
                    const uint8_t *key,
                    const uint8_t *iv
                );
            
            
#endif