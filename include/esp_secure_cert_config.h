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
#define ESP_SECURE_CERT_METADATA_MAGIC_WORD     0x12345678

#define ESP_SECURE_CERT_METADATA_OFFSET         0
#define ESP_SECURE_CERT_METADATA_SIZE           16
#define ESP_SECURE_CERT_TABLE_MAX_ENTRIES       25
#define ESP_SECURE_CERT_TABLE_OFFSET + ESP_SECURE_CERT_HEADER_SIZE
#define ESP_SECURE_CERT_TABLE_MAX_SIZE          256
#define ESP_SECURE_CERT_DATA_OFFSET ESP_SECURE_CERT_TABLE_OFFSET + ESP_SECURE_CERT_TABLE_MAX_SIZE

enum esp_secure_cert_type {
    ESP_SECURE_CERT_INVALID_TYPE = -1;
    ESP_SECURE_CERT_CA_CERT,
    ESP_SECURE_CERT_DEV_CERT,
    ESP_SECURE_CERT_PRIV_KEY,
    ESP_SECURE_CERT_DS_CONTEXT,
    ESP_SECURE_CERT_UNKNOWN,
} esp_secure_cert_type_t;

esp_secure_cert_tlv_t {
    esp_secure_cert_type_t type;        /* Type of data */
    uint8_t length;                     /* Length of data in bytes */
    uint8_t *value;                     /* actual data in form of byte array */
}

typedef struct {
    uint8_t magic;
    esp_secure_cert_type_t type; /* type of the data */
    uint8_t length; /* length of the data */
    uint8_t offset; /* offset of the data from the base of esp_secure_cert partition */
} esp_secure_cert_info_t;

typedef struct {
    uint8_t magic_word;         /* Magic word */
    uint8_t segment_count;      /* Count of segments */
    uint32_t addr;              /* Start of the data stored in tlv format*/
    bool table_updated;         /* Status of table containing info about tlv data segments */
} __attribute__((packed))  esp_secure_cert_metadata_t;
#endif


#else
#error "Invalid type of partition selected"
#endif
