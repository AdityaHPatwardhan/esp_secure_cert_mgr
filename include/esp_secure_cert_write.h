/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "esp_secure_cert_config.h"
#include "esp_secure_cert_read.h"

#ifdef CONFIG_ESP_SECURE_CERT_DS_PERIPHERAL
#include "rsa_sign_alt.h"
#endif
#ifdef CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION

/* @info
 * Write the tlv in the flash
 *
 * @params
 *
 * type              Type of the tlv structure.
 * data              It should contain a pointer to a readable buffer containing the data to be written to flash
 * data_len          The length of the data in bytes
 * @return
 *      - ESP_OK on success
 *      - ESP_FAIL/other relevant esp error code on failure
 */
esp_err_t esp_secure_cert_write(esp_secure_cert_tlv_type_t type, const unsigned char *data, uint16_t data_len);

/*  @info
 *  Prepare the tlv structure of the given data
 *  @params
 *
 *  type        type of tlv
 *  value       Buffer containing the data to be written to the tlv
 *  value_len   Length of the data in bytes
 *  output_buf  The output buffer where the generated tlv shall be stored
 *  output_len  The length of the final tlv structure
 *  output_len  (input/output)
 *              input : This should contain the length of the output buffer
 *              output: This value shall be updated with the actual output length
  * @return
 *      - ESP_OK    On success
 *      - ESP_FAIL/other relevant esp error code
 *                  On failure
 */
esp_err_t esp_secure_cert_prepare_tlv(esp_secure_cert_tlv_type_t type, const unsigned char *value, size_t value_len, unsigned char *output_buf, size_t *output_len);
#endif
