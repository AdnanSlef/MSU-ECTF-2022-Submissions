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
 * TODO Documentation
 * 
 * @brief Decapsulates an AEAD package, verifying authorization.
 * 
 * @param pt Buffer 
 * @return TODO 0 on success, or -1 if an invalid block address was specified or the 
 * block is write-protected.
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

#endif