/**
 * @file bootloader.c
 * @author Spartans
 * @brief Bootloader implementation
 * @date 2022
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "driverlib/interrupt.h"
#include "flash.h"
#include "uart.h"
#include "driverlib/eeprom.h"
#include "driverlib/sysctl.h"

#include "aead.h"
#include "gcm.h"

#ifdef DO_MAKE_SWEET_B
#include "sb_all.h"
#endif

// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01

#define SPAR 0x72617053
#define TANS 0x736e6174

// Storage Layout

/*
 * Firmware:
 *      Ct:       0x00020400 : 0x00024400 (16KB)
 *      Size:     0x00024400 : 0x00024404 (4B)
 *      IV:       0x00024404 : 0x00024410 (12B)
 *      Tag:      0x00024410 : 0x00024420 (16B)
 *      Version:  0x00024420 : 0x00024424 (4B)
 *      Msg:      0x00024800 : 0x00024C00 (1KB)
 *      Msg:      0x00024C00 : 0x00024C04 (4B)
 *      Fw_Boot:  0x20004000 : 0x20008000 (16KB)
 * Configuration:
 *      Ct:       0x00010000 : 0x00020000 (64KB)
 *      Size:     0x00020000 : 0x00020004 (4B)
 *      IV:       0x00020004 : 0x00020010 (12B)
 *      Tag:      0x00020010 : 0x00020020 (16B)
 *      Cfg_Boot: 0x00030000 : 0x00040000 (64KB)
 * Temporary:
 *      Mem:      0x00030000 : 0x00040000 (64KB)
 *      Size:     0x20004000 : 0x20004004 (4B)
 *      IV:       0x20004004 : 0x20004010 (12B)
 *      Tag:      0x20004010 : 0x20004020 (16B)
 *      Version:  0x20004020 : 0x20004024 (4B)
 *      Msg:      0x20004400 : 0x20004800 (1KB)
 */


#define CONFIGURATION_STORAGE_PTR  ((uint32_t)(FLASH_START + 0x00010000))
#define CONFIGURATION_METADATA_PTR ((uint32_t)(CONFIGURATION_STORAGE_PTR + (FLASH_PAGE_SIZE*64)))
#define CONFIGURATION_SIZE_PTR     ((uint32_t)(CONFIGURATION_METADATA_PTR + 0))
#define CONFIGURATION_IV_PTR       ((uint32_t)(CONFIGURATION_METADATA_PTR + 4))
#define CONFIGURATION_TAG_PTR      ((uint32_t)(CONFIGURATION_METADATA_PTR + 16))
#define CONFIGURATION_BOOT_PTR     ((uint32_t)(CONFIGURATION_STORAGE_PTR + (FLASH_PAGE_SIZE*128)))

#define FIRMWARE_STORAGE_PTR       ((uint32_t)(CONFIGURATION_METADATA_PTR + FLASH_PAGE_SIZE))
#define FIRMWARE_METADATA_PTR      ((uint32_t)(FIRMWARE_STORAGE_PTR + (FLASH_PAGE_SIZE*16)))
#define FIRMWARE_SIZE_PTR          ((uint32_t)(FIRMWARE_METADATA_PTR + 0))
#define FIRMWARE_IV_PTR            ((uint32_t)(FIRMWARE_METADATA_PTR + 4))
#define FIRMWARE_TAG_PTR           ((uint32_t)(FIRMWARE_METADATA_PTR + 16))
#define FIRMWARE_VERSION_PTR       ((uint32_t)(FIRMWARE_METADATA_PTR + 32))
#define FIRMWARE_RELEASE_MSG_PTR   ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE))
#define FIRMWARE_RELEASE_SIZE_PTR  ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE*2))
#define FIRMWARE_BOOT_PTR          ((uint32_t)0x20004000)

#define TEMP_MEM_PTR CONFIGURATION_BOOT_PTR
#define TEMP_METADATA_PTR FIRMWARE_BOOT_PTR
#define TEMP_SIZE_PTR              ((uint32_t)(TEMP_METADATA_PTR + 0))
#define TEMP_IV_PTR                ((uint32_t)(TEMP_METADATA_PTR + 4))
#define TEMP_TAG_PTR               ((uint32_t)(TEMP_METADATA_PTR + 16))
#define TEMP_VERSION_PTR           ((uint32_t)(TEMP_METADATA_PTR + 32))
#define TEMP_RELEASE_MSG_PTR       ((uint32_t)(TEMP_METADATA_PTR + FLASH_PAGE_SIZE))


// EEPROM Layout
struct eeprom_s {
    uint8_t fw_key[16];
    uint8_t cfg_key[16];
    uint8_t auth_key[16];
    char msg[16];
};
#define EEPROM_GET(dst, obj) do {\
    EEPROMInit();\
    EEPROMRead( (uint32_t *) &(dst), offsetof(struct eeprom_s, obj), sizeof((dst)));\
} while(0)



/**
 * @brief Wipes temporary data
 */
void clear_temp(void)
{
    int i;

    // Wipe Flash Temp
    for(i = 0; i < 64; i++) {
        flash_erase_page(TEMP_MEM_PTR + FLASH_PAGE_SIZE * i);
    }

    // Wipe SRAM Temp
    memset((void *)TEMP_METADATA_PTR, 0, FLASH_PAGE_SIZE * 2);
}

/**
 * @brief Copy data and program to flash memory.
 * 
 * @param dst is the starting page address to store the data.
 * @param src is the address to copy data from.
 * @param size is the number of bytes to copy.
 */
void copy_data_flash(uint32_t dst, const uint8_t * src, uint32_t size)
{
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    while(size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read frame into buffer
        memcpy(page_buffer, src, frame_size);
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
        src += FLASH_PAGE_SIZE;
        size -= frame_size;
    }
}

/**
 * @brief Read data from a UART interface and program to flash memory.
 * 
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 */
void load_data(uint32_t interface, uint32_t dst, uint32_t size)
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
        uart_writeb(HOST_UART, FRAME_OK);
    }
}

/**
 * @brief Boot the firmware.
 */
void handle_boot(void)
{
    uint32_t size;
    uint32_t i = 0;
    uint8_t *rel_msg;
    uint8_t aad[16+FLASH_PAGE_SIZE];
    uint32_t version;
    uint32_t rel_msg_size;
    uint8_t key[KEY_LEN];
    int err;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');
    
    // Wipe temporary storage
    clear_temp();

    // Find the metadata
    size = *((uint32_t *)FIRMWARE_SIZE_PTR);

    // Reject invalid size
    if (size > FLASH_PAGE_SIZE * 16) {
        uart_writeb(HOST_UART, 'E');
        return;
    }

    // Find the release message
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;

    // Calculate release message length
    for(i = 1024; i && *rel_msg; i--) {rel_msg++;}
    rel_msg_size = 1024 - i;
    rel_msg -= rel_msg_size;

    // Decapsulate Protected Firmware for boot
    version = *(uint32_t *)FIRMWARE_VERSION_PTR;
    ((uint32_t *)aad)[0] = version;
    ((uint32_t *)aad)[1] = *(uint32_t *)FIRMWARE_RELEASE_SIZE_PTR; //rel_msg_size
    ((uint32_t *)aad)[2] = SPAR;
    ((uint32_t *)aad)[3] = TANS;
    memcpy(aad+16, rel_msg, rel_msg_size);
    EEPROM_GET(key, fw_key);
    err = aead_dec( (uint8_t *)FIRMWARE_BOOT_PTR,
                    (uint8_t *)FIRMWARE_STORAGE_PTR,
                    *(uint32_t *)FIRMWARE_SIZE_PTR,
                    aad,
                    16,
                    key,
                    (uint8_t *)FIRMWARE_IV_PTR,
                    (uint8_t *)FIRMWARE_TAG_PTR
                );
    memset(key, 0, sizeof(key));

    // Handle Error
    if(err) {
        uart_writeb(HOST_UART, 'E');
        return;
    }

    // Get Configuration Metadata
    size = *(uint32_t *)CONFIGURATION_SIZE_PTR;
    
    // Reject invalid size
    if (size > FLASH_PAGE_SIZE * 64) {
        uart_writeb(HOST_UART, 'E');
        return;
    }

    // Decapsulate Protected Configuration for boot
    EEPROM_GET(key, cfg_key);
    err = flash_dec( CONFIGURATION_BOOT_PTR,
                    (uint8_t *)CONFIGURATION_STORAGE_PTR,
                    *(uint32_t *)CONFIGURATION_SIZE_PTR,
                    NULL,
                    0,
                    key,
                    (uint8_t *)CONFIGURATION_IV_PTR,
                    (uint8_t *)CONFIGURATION_TAG_PTR
                );
    memset(key, 0, sizeof(key));

    // Handle Error
    if(err) {
        uart_writeb(HOST_UART, 'E');
        return;
    }

    // Respond to boot host tool
    uart_writeb(HOST_UART, 'M');

    // Print the release message
    for(i = 1024; i && *rel_msg; i--) {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');

    // Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}


/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void)
{
    uint8_t region;
    uint8_t *address;
    uint32_t size = 0;
    uint32_t max_size;
    uint8_t auth[16];
    uint8_t guess[16];
    uint8_t key[KEY_LEN];
    uint8_t *iv;
    
    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F') {
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        max_size = *((uint32_t *)FIRMWARE_SIZE_PTR);
        max_size = max_size > FLASH_PAGE_SIZE*16 ? FLASH_PAGE_SIZE*16 : max_size;
        iv = (uint8_t *)FIRMWARE_IV_PTR;
        EEPROM_GET(key, fw_key);
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        max_size = *((uint32_t *)CONFIGURATION_SIZE_PTR);
        max_size = max_size > FLASH_PAGE_SIZE*64 ? FLASH_PAGE_SIZE*64 : max_size;
        iv = (uint8_t *)CONFIGURATION_IV_PTR;
        EEPROM_GET(key, cfg_key);
        // Acknowledge the hose
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }

    // Receive the size to send back to the host
    size  = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Authorize request
    for(int i = 0; i < sizeof(guess); i++) {
        guess[i] = uart_readb(HOST_UART);
    }
    EEPROM_GET(auth, auth_key);
    if(size > max_size || !is_equal(auth, guess, sizeof(auth))) {
        uart_writeb(HOST_UART, '0');
        return;
    }
    uart_writeb(HOST_UART, '1');
    memset(auth, 0, sizeof(auth));
    memset(guess, 0, sizeof(auth));

    // Fulfill Request
    readback_dec(address, size, key, iv);
    memset(key, 0, sizeof(key));
}

/**
 * @brief Update the firmware.
 */
void handle_update(void)
{
    uint32_t current_version;
    uint32_t version = 0;
    uint32_t size = 0;
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t key[KEY_LEN];
    uint8_t aad[16+1025] = {0};
    uint8_t *rel_msg = aad+16;
    uint32_t rel_msg_size = 0;
    uint32_t rel_msg_write_size = 0;
    uint32_t iter;
    int err;
    int i;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'U');

    // Receive version
    version = ((uint32_t)uart_readb(HOST_UART)) << 8;
    version |= (uint32_t)uart_readb(HOST_UART);

    // Receive size
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Receive iv
    for(iter = 0; iter < sizeof(iv); iter++) {
        iv[iter] = uart_readb(HOST_UART);
    }

    // Receive tag
    for(iter = 0; iter < sizeof(tag); iter++) {
        tag[iter] = uart_readb(HOST_UART);
    }

    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, rel_msg, sizeof(aad)-16) + 1;

    // Reject invalid size
    if (size > FLASH_PAGE_SIZE * 16) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }
    if ((version != 0) && (version < current_version) || (version > 0xFFFF)) {
        // Version is not acceptable
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Acknowledge
    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve firmware
    load_data(HOST_UART, TEMP_MEM_PTR, size);

    // Calculate release message length
    for(i = 1024; i && *rel_msg; i--) {rel_msg++;}
    rel_msg_size = 1024 - i;
    rel_msg -= rel_msg_size;

    // Adjust write size
    rel_msg_write_size = rel_msg_size;
    if(rel_msg_size != FLASH_PAGE_SIZE) rel_msg_write_size++;
    if(rel_msg_write_size % 4) {
        rel_msg_write_size += 4 - (rel_msg_size % 4);
    }

    // Check signature
    ((uint32_t *)aad)[0] = version;
    ((uint32_t *)aad)[1] = rel_msg_size;
    ((uint32_t *)aad)[2] = SPAR;
    ((uint32_t *)aad)[3] = TANS;
    EEPROM_GET(key, fw_key);
    err = check_sig( (uint8_t *)TEMP_MEM_PTR,
                    size,
                    aad,
                    16,
                    key,
                    iv,
                    tag
                );
    memset(key, 0, KEY_LEN);

    // Handle Invalid Signature
    if(err) {
        uart_writeb(HOST_UART, 'E');
        clear_temp();
        return;
    }

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Save metadata
    flash_write_word(size, FIRMWARE_SIZE_PTR);
    flash_write_word(rel_msg_size, FIRMWARE_RELEASE_SIZE_PTR);
    flash_write((uint32_t *)iv, FIRMWARE_IV_PTR, IV_LEN >> 2);
    flash_write((uint32_t *)tag, FIRMWARE_TAG_PTR, TAG_LEN >> 2);

    // Update stored version number
    if (version == 0xFFFF) {
        // Disallow further updates after 0xFFFF
        flash_write_word(0, FIRMWARE_VERSION_PTR);
    }
    else if (version != 0) {
        // Update current version to loaded version
        flash_write_word(version, FIRMWARE_VERSION_PTR);
    } else {
        // Do not change current version when loading version 0
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Clear release message
    flash_erase_page(FIRMWARE_RELEASE_MSG_PTR);

    // Write release message
    flash_write((uint32_t *)rel_msg, FIRMWARE_RELEASE_MSG_PTR, rel_msg_write_size >> 2);
    uart_write(HOST_UART, (uint8_t *)FIRMWARE_RELEASE_MSG_PTR, 16);

    // Accept Firmware Update
    copy_data_flash(FIRMWARE_STORAGE_PTR, (uint8_t *)TEMP_MEM_PTR, size);
    uart_writeb(HOST_UART, FRAME_OK);
}


/**
 * @brief Load configuration data.
 */
void handle_configure(void)
{
    uint32_t size = 0;
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t key[KEY_LEN];
    uint32_t iter;
    int err;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    // Receive size
    size = (((uint32_t)uart_readb(HOST_UART)) << 24);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    size |= ((uint32_t)uart_readb(HOST_UART));

    // Receive iv
    for(iter = 0; iter < sizeof(iv); iter++) {
        iv[iter] = uart_readb(HOST_UART);
    }

    // Receive tag
    for(iter = 0; iter < sizeof(tag); iter++) {
        tag[iter] = uart_readb(HOST_UART);
    }

    // Reject invalid size
    if (size > FLASH_PAGE_SIZE * 64) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);
    
    // Retrieve configuration
    load_data(HOST_UART, TEMP_MEM_PTR, size);

    // Check signature
    EEPROM_GET(key, cfg_key);
    err = check_sig( (uint8_t *)TEMP_MEM_PTR,
                    size,
                    NULL,
                    0,
                    key,
                    iv,
                    tag
                );
    memset(key, 0, KEY_LEN);

    // Handle Invalid Signature
    if(err) {
        uart_writeb(HOST_UART, 'E');
        clear_temp();
        return;
    }

    // Write Configuration Metadata
    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write_word(size, CONFIGURATION_SIZE_PTR);
    flash_write((uint32_t *)iv, CONFIGURATION_IV_PTR, IV_LEN >> 2);
    flash_write((uint32_t *)tag, CONFIGURATION_TAG_PTR, TAG_LEN >> 2);
    
    // Accept Configuration Update
    copy_data_flash(CONFIGURATION_STORAGE_PTR, (uint8_t *)TEMP_MEM_PTR, size);
    uart_writeb(HOST_UART, FRAME_OK);
    uart_write(HOST_UART, (uint8_t *)CONFIGURATION_STORAGE_PTR, 16);
}

/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 * 
 * @return int
 */
int main(void) {

    uint8_t cmd = 0;

    // Initialize IO components
    uart_init();
    
    // Initialize EEPROM
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    // Initialize Cryptographic Library
    gcm_initialize();

    // Handle host commands
    while (1) {
        cmd = uart_readb(HOST_UART);

        switch (cmd) {
        case 'C':
            handle_configure();
            break;
        case 'U':
            handle_update();
            break;
        case 'R':
            handle_readback();
            break;
        case 'B':
            handle_boot();
            break;
        default:
            break;
        }
    }
}
