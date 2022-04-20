/**
 * @file AEAD.h
 * @author Spartans
 * @brief Bootloader symmetric encryption implementation.
 * @date 2022
 */

#include <stdint.h>

#include "aead.h"
#include "gcm.h"

#include "uart.h"
#include "flash.h"

#define DEBUG_AEAD //TODO

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
            )
{
    uint32_t err = 0;
    gcm_context ctx;
    
    uint8_t tag_buf[16];
    
    // Set Symmetric Key
    gcm_setkey( &ctx, key, KEY_LEN );

    // Perform Decryption    
    gcm_start  ( &ctx, DECRYPT, iv, IV_LEN, aad, aad_len );
    gcm_update ( &ctx, ct_len, ct, pt );
    gcm_finish ( &ctx, tag_buf, TAG_LEN );
    
    // Clear GCM Context
    gcm_zero_ctx( &ctx );

    #ifdef DEBUG_AEAD
    uart_write(HOST_UART, aad, 16);
    #endif
    // Validate signature
    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    if(err) {
        memset(pt, 0, ct_len);
    }

    return err;

}

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
            )
{
    
    int err = 0;
    gcm_context ctx;

    uint8_t pt[0x400];
    size_t left = ct_len;
    size_t part_len;
    
    uint8_t tag_buf[16];
    
    // Set Symmetric Key
    gcm_setkey( &ctx, key, KEY_LEN );

    // Perform Decryption    
    gcm_start  ( &ctx, DECRYPT, iv, IV_LEN, aad, aad_len );
    while(left) {
        part_len = (left < sizeof(pt)) ? left : sizeof(pt);
        gcm_update ( &ctx, part_len, ct+ct_len-left, pt );
        left -= part_len;
    }
    gcm_finish ( &ctx, tag_buf, TAG_LEN );
    
    // Clear GCM Context
    gcm_zero_ctx( &ctx );

    #ifdef DEBUG_AEAD
    uart_write(HOST_UART, tag_buf, 16);
    uart_write(HOST_UART, tag, 16);
    uart_write(HOST_UART, pt, 16);
    if(aad) {
        uart_write(HOST_UART, aad, 16);
    }
    #endif

    // Validate signature
    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    memset(pt, 0, ct_len);

    return err;

}

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
                )
{
    
    gcm_context ctx;

    uint8_t pt[0x400];
    size_t left = ct_len;
    size_t part_len;
    
    // Set Symmetric Key
    gcm_setkey( &ctx, key, KEY_LEN );

    // Perform Decryption    
    gcm_start(&ctx, DECRYPT, iv, IV_LEN, NULL, 0);
    while(left) {
        part_len = (left < sizeof(pt)) ? left : sizeof(pt);
        gcm_update ( &ctx, part_len, ct+ct_len-left, pt );
        uart_write(HOST_UART, pt, part_len);
        left -= part_len;
    }

    // Clear GCM Context
    gcm_zero_ctx( &ctx );
    
    memset(pt, 0, ct_len);

    return;
}

/**
 * @brief Decrypts data into flash
 * 
 * @param flash    Output address
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
int flash_dec(  uint32_t flash,
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

    uint8_t pt[FLASH_PAGE_SIZE];
    size_t left = ct_len;
    size_t part_len;
    
    uint8_t tag_buf[16];
    
    // Set Symmetric Key
    gcm_setkey( &ctx, key, KEY_LEN );

    // Perform Decryption    
    gcm_start(&ctx, DECRYPT, iv, IV_LEN, NULL, 0);
    while(left) {
        part_len = (left < sizeof(pt)) ? left : sizeof(pt);
        gcm_update ( &ctx, part_len, ct+ct_len-left, pt );
        flash_erase_page(flash);
        flash_write((uint32_t *)pt, flash, part_len >> 2);
        flash += FLASH_PAGE_SIZE;
        left -= part_len;
    }
    gcm_finish(&ctx, tag_buf, TAG_LEN);
        
    // Clear GCM Context
    gcm_zero_ctx( &ctx );

    // Validate signature
    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    if(err) {
        left = ct_len;
        while(left) {
            part_len = (left < FLASH_PAGE_SIZE) ? left : FLASH_PAGE_SIZE;
            flash -= FLASH_PAGE_SIZE;
            flash_erase_page(flash);
            left -= part_len;
        }
    }

    return err;
}


