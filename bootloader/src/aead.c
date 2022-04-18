/**
 * @file AEAD.h
 * @author Spartans
 * @brief Bootloader symmetric encryption implementation.
 * @date 2022
 */

#include <stdint.h>

#include "aead.h"
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
int is_equal(const uint8_t *a, const uint8_t *b, const size_t len) {
    int differ = 0;
    int i;
    for(i = 0; i < len; i++) {
        differ |= a[i]^b[i];
    }
    return !differ;
}

/**
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
            )
{
    
    int err = 0;
    gcm_context ctx;
    
    uint8_t tag_buf[16];
    
    gcm_setkey( &ctx, key, KEY_LEN );
    
    err = gcm_crypt_and_tag(&ctx, DECRYPT,
                            iv, IV_LEN,
                            aad, aad_len,
                            ct, pt, ct_len,
                            tag_buf, TAG_LEN);
    
    gcm_zero_ctx( &ctx );

    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    if(err) {
        memset(pt, 0, ct_len);
    }

    return err;

}


/***************** Test Functions *****************/

/*
int test_aead_enc()
{
    int ret = 0;                // our return value
    gcm_context ctx;            // includes the AES context structure
    uchar ct_buf[256];          // cipher text results for comparison
    uchar tag_buf[16];          // tag result buffer for comparison

    gcm_setkey( &ctx, key, (const uint)key_len );   // setup our AES-GCM key

    // encrypt the NIST-provided plaintext into the local ct_buf and
    // tag_buf ciphertext and authentication tag buffers respectively.
    ret = gcm_crypt_and_tag( &ctx, ENCRYPT, iv, iv_len, aad, aad_len,
                             pt, ct_buf, ct_len, tag_buf, tag_len);
    ret |= memcmp( ct_buf, ct, ct_len );    // verify correct ciphertext
    ret |= memcmp( tag_buf, tag, tag_len ); // verify correct authentication tag

    gcm_zero_ctx( &ctx );       // not really necessary here, but good to do

    return ( ret );             // return any error 'OR' generated above
}
*/