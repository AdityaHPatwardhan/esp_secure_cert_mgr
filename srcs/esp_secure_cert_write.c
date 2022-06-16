#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "esp_crc.h"
#include "esp_secure_cert_config.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_write.h"
#include "esp_secure_cert_private.h"
#include "nvs_flash.h"

static const char *TAG = "esp_secure_cert_write";

#ifdef CONFIG_ESP_SECURE_CERT_CUST_FLASH_PARTITION

/*  Write the data to flash at particular offset
 *  @params
 *  offset
 *      The offset from the start of the esp_secure_cert partition.
 *  data_buf
 *      The buffer containing the data to be flashed
 *  data_len
 *      The length of the data in bytes
 *  Note:
 *      This API cannot be used when flash encryption is enabled. When flash encryption is enabled
 *      the esp_partition_write requires a 32 byte aligned flash address and 32 byte aligned data buffer.
 *      This API does not take care of that.
 **/
static esp_err_t esp_secure_cert_write_to_flash(size_t offset, unsigned char *data_buf, size_t data_len)
{
    assert(data_buf);
    ESP_LOGD(TAG, "the data of length %d bytes shall be flashed at an offset of %d"
            "from the base address of esp_secure_cert partition", data_len, offset);

    esp_partition_iterator_t it = esp_partition_find(ESP_SECURE_CERT_PARTITION_TYPE, ESP_PARTITION_SUBTYPE_ANY, ESP_SECURE_CERT_PARTITION_NAME);
    if (it == NULL) {
        ESP_LOGI(TAG, "Could not find esp_secure_cert partition.");
        return ESP_FAIL;
    }

    const esp_partition_t *part = esp_partition_get(it);
    if (part == NULL) {
        ESP_LOGI(TAG, "Could not get esp_secure_cert partition.");
        return ESP_FAIL;
    }

    esp_err_t err = ESP_FAIL;
    err = esp_partition_write(part, offset, data_buf, data_len);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "Could not write to esp_secure_cert partition.");
        return err;
    }

    return ESP_OK;
}

/* Prepare the tlv structure of the given data
 * @params
 *  type        type of tlv
 *  value       Buffer containing the data to be written to the tlv
 *  value_len   Length of the data in bytes
 *  output_buf  The output buffer where the generated tlv shall be stored
 *  output_len  The length of the final tlv structure
 *  output_len  (input/output)
 *              input : This should contain the length of the output buffer
 *              output: This value shall be updated with the actual output length
 */
esp_err_t esp_secure_cert_prepare_tlv(esp_secure_cert_tlv_type_t type, const unsigned char *value, size_t value_len, unsigned char *output_buf, size_t *output_len)
{
    size_t data_len = 0;
    size_t required_buf_len = sizeof(esp_secure_cert_tlv_header_t) + sizeof(esp_secure_cert_tlv_footer_t) + value_len;
    if (*output_len < data_len) {
        ESP_LOGE(TAG, "buffer len = %d is smaller than the required size = %d", *output_len, required_buf_len);
        return ESP_ERR_INVALID_ARG;
    }
    esp_secure_cert_tlv_header_t tlv_header;
    memset((void*)&tlv_header, 0, sizeof(esp_secure_cert_tlv_header_t));
    tlv_header.type = type;
    tlv_header.magic = ESP_SECURE_CERT_MAGIC;
    tlv_header.length = value_len;
    memset(output_buf, 0, *output_len);
    memcpy(output_buf, &tlv_header, sizeof(esp_secure_cert_tlv_header_t));
    data_len = data_len + sizeof(esp_secure_cert_tlv_header_t);
    memcpy(output_buf + data_len, value, value_len);
    data_len = data_len + value_len;
    uint32_t crc_data = 0;
    crc_data = esp_crc32_le(UINT32_MAX, (const uint8_t * )output_buf, data_len);
    esp_secure_cert_tlv_footer_t tlv_footer;
    tlv_footer.crc = crc_data;
    memcpy(output_buf + data_len, &tlv_footer, sizeof(esp_secure_cert_tlv_footer_t));
    *output_len = data_len;
    return ESP_OK;
}

esp_err_t esp_secure_cert_write(esp_secure_cert_tlv_type_t type, const unsigned char *data, uint16_t data_len)
{
    esp_err_t err;
    const void *esp_secure_cert_addr = esp_secure_cert_get_mapped_addr();
    /* This variable shall store the end address of the last tlv
     * in esp_secure_cert where the next data shall be written */
    static int tlv_end_offset;
    void *tlv_address = NULL;
    if (tlv_end_offset == 0) {
        err = esp_secure_cert_find_tlv(esp_secure_cert_addr, ESP_SECURE_CERT_TLV_END, &tlv_address);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Error in getting the tlv end address");
        }
    }

    err = esp_secure_cert_find_tlv(esp_secure_cert_addr, type, &tlv_address);
    if (err == ESP_OK) {
        ESP_LOGE(TAG, "tlv of type %d already exists. There can only be one tlv of any given type in esp_secure_cert partiton");
        return ESP_FAIL;
    }

    size_t required_buf_len = data_len + sizeof(esp_secure_cert_tlv_header_t) + sizeof(esp_secure_cert_tlv_footer_t);
    uint8_t *output_buf;
    output_buf = (uint8_t *) calloc(1, (required_buf_len + 1) * sizeof(uint8_t));
    if (output_buf == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for internal buffer");
        return ESP_ERR_NO_MEM;
    }

    size_t output_len = 0;
    esp_secure_cert_prepare_tlv(type, data, data_len, output_buf, &output_len);
    // output_buf should now contain the required tlv structrure that needs to be written to the flash
    // This buffer shall now be written at tlv_end_offset
    ESP_LOGI(TAG, "the end address of last tlv structure is %d", tlv_end_offset);
    err = esp_secure_cert_write_to_flash(tlv_end_offset, output_buf, output_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write the tlv of type %d to flash, returned %02X", type, err);
        free(output_buf);
        return ESP_FAIL;
    }
    // Update the tlv_end_offset variable to directly start flashing at this offset at the next flash write operation
    tlv_end_offset = tlv_end_offset + required_buf_len;
    free(output_buf);
    return ESP_OK;
}
#endif
