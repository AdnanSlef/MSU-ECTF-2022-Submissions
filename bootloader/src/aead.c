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

    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    if(err) {
        memset(pt, 0, ct_len); //TODO erase flash instead if appropriate
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

    //TODO rmv debug
    uart_write(HOST_UART, tag_buf, 16);
    uart_write(HOST_UART, tag, 16);
    uart_write(HOST_UART, pt, 16);

    if (!is_equal(tag_buf, tag, 16)) {
        err = GCM_AUTH_FAILURE;
    }

    //TODO rmv debug
    uart_write(HOST_UART, (uint8_t *)&err, 4);

    memset(pt, 0, ct_len);

    //TODO rmv debug
    // uart_write(HOST_UART, "by", 2);

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
    
    int err = 0;
    gcm_context ctx;

    uint8_t pt[0x400];
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
        uart_write(HOST_UART, pt, part_len);
        left -= part_len;
    }
    
    memset(pt, 0, ct_len);

    return;
}

/**
 * @brief TODO Read data from a UART interface and program to flash memory.
 * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
void flash_dec(uint32_t interface, uint32_t dst, uint32_t size)
{
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        uart_read(HOST_UART, page_buffer, frame_size);
        // pad buffer if frame is smaller than the page
        for(i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        // uart_writeb(HOST_UART, FRAME_OK);
    }
}