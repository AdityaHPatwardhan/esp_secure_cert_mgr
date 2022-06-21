/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <stdint.h>

#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
#include "esp_ds.h"
#endif

#define ESP_SECURE_CERT_PKEY_MAGIC_BYTE        0xC1   /* Magic byte of the generated private key */
#define ESP_SECURE_CERT_DEV_CERT_MAGIC_BYTE    0xC2   /* Magic byte of the generated device certificate */
#define ESP_SECURE_CERT_CA_CERT_MAGIC_BYTE     0xC3   /* Magic byte of the CA certificate */

#ifdef CONFIG_ESP_SECURE_CERT_NVS_PARTITION
/* NVS Config */
#define ESP_SECURE_CERT_NVS_PARTITION       CONFIG_ESP_SECURE_CERT_PARTITION_NAME
#define ESP_SECURE_CERT_NVS_KEYS_PARTITION  CONFIG_ESP_SECURE_CERT_KEYS_PARTITION_NAME

#define ESP_SECURE_CERT_PRIV_KEY            "priv_key"
#define ESP_SECURE_CERT_DEV_CERT            "dev_cert"
#define ESP_SECURE_CERT_CA_CERT             "ca_cert"
#define ESP_SECURE_CERT_NAMESPACE           CONFIG_ESP_SECURE_CERT_PARTITION_NAME

#define ESP_SECURE_CERT_CIPHERTEXT          "cipher_c"
#define ESP_SECURE_CERT_RSA_LEN             "rsa_len"
#define ESP_SECURE_CERT_EFUSE_KEY_ID        "ds_key_id"
#define ESP_SECURE_CERT_IV                  "iv"

#elif CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION

#define ESP_SECURE_CERT_PARTITION_TYPE          0x3F        /* Custom partition type */
#define ESP_SECURE_CERT_PARTITION_NAME          CONFIG_ESP_SECURE_CERT_PARTITION_NAME  /* Name of the custom esp_secure_cert partition */
#define ESP_SECURE_CERT_MAGIC                   0xFEEDBABE
#define ESP_SECURE_CERT_PARTITION_SIZE          CONFIG_ESP_SECURE_CERT_PARTITION_SIZE
#define ESP_SECURE_CERT_DATA_OFFSET             0

/* secure cert partition is of 12 KB size out of which 6-7 KB are utilized stored parameters, the additional space is reserved for future use */
typedef enum esp_secure_cert_type {
    ESP_SECURE_CERT_CA_CERT = 0,
    ESP_SECURE_CERT_DEV_CERT,
    ESP_SECURE_CERT_PRIV_KEY,
    ESP_SECURE_CERT_DS_DATA,
    ESP_SECURE_CERT_DS_CONTEXT,
    ESP_SECURE_CERT_TLV_END,
    //Custom data types
    //that can be defined by the user
    ESP_SECURE_CERT_USER_DATA_1,
    ESP_SECURE_CERT_USER_DATA_2,
    ESP_SECURE_CERT_USER_DATA_3,
} esp_secure_cert_tlv_type_t;

typedef struct esp_secure_cert_tlv_header {
    uint32_t magic;
    uint8_t type;                       /* Type of tlv structure, this shall be typecasted
                                           to esp_secure_cert_tlv_type_t for further use */
    uint16_t length;                    /* Length of the data */
    uint8_t value[0];                   /* Actual data in form of byte array */
} __attribute__((packed)) esp_secure_cert_tlv_header_t;

typedef struct esp_secure_cert_tlv_footer {
    uint32_t crc;                       /* crc of the data */
} esp_secure_cert_tlv_footer_t;

/*
 *
 * The data stored in a cust flash partition should be as follows:
 *
 * tlv_header1 -> data_1 -> tlv_footer1 -> tlv_header2...
 *
 */

#else
#error "Invalid type of partition selected"
#endif
