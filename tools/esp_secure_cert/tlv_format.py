import binascii
import enum
import struct
import zlib
from esp_secure_cert.esp_secure_cert_helper import (
        load_private_key,
        load_certificate
)
from cryptography.hazmat.primitives import serialization

tlv_type_subtype_set = set()


class tlv_type_t(enum.IntEnum):
    CA_CERT = 0
    DEV_CERT = 1
    PRIV_KEY = 2
    DS_DATA = 3
    DS_CONTEXT = 4
    ECDSA_KEY_SALT = 5
    SEC_CFG = 6
    TLV_END = 50
    USER_DATA_1 = 51
    USER_DATA_2 = 52
    USER_DATA_3 = 53
    USER_DATA_4 = 54
    USER_DATA_5 = 55


class tlv_priv_key_type_t(enum.IntEnum):
    ESP_SECURE_CERT_INVALID_KEY = -1
    ESP_SECURE_CERT_DEFAULT_FORMAT_KEY = 0
    ESP_SECURE_CERT_HMAC_ENCRYPTED_KEY = 1
    ESP_SECURE_CERT_HMAC_DERIVED_ECDSA_KEY = 2
    ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY = 3
    ESP_SECURE_CERT_RSA_DS_PERIPHERAL_KEY = 4


class tlv_priv_key_t:
    def __init__(self, key_type: tlv_priv_key_type_t,
                 key_path, key_pass):
        self.key_type = key_type
        self.key_path = key_path
        self.key_pass = key_pass
        self.efuse_key_id = -1
        self.salt = None
        self.ciphertext = None
        self.iv = None
        self.priv_key_len = 0
        self.priv_key_format = None


# This is the minimum required flash address alignment to write
# to an encrypted partition on esp device
MIN_ALIGNMENT_REQUIRED = 16


def _get_tlv_header_key_info_byte(key_type):
    '''
    Set Nth bit to one in the given number
    @input
    flags     Input Number
    N         The number of bit to be set to 1
    '''
    def _set_bit(flags, N):
        return flags | (1 << N)
    flags = 0
    if key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_HMAC_ENCRYPTED_KEY:
        flags = _set_bit(flags, 7)  # i.e. 2 << 6

    if key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_HMAC_DERIVED_ECDSA_KEY:
        flags = _set_bit(flags, 6)

    if key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY:
        flags = _set_bit(flags, 3)

    return hex(flags)


def prepare_tlv(tlv_type, tlv_subtype, tlv_type_info, data, data_len):
    check_tlv_uniqueness(tlv_type, tlv_subtype)
    tlv_type_subtype_set.add((tlv_type, tlv_subtype))

    # Add the magic at start ( unsigned int )
    tlv_header = struct.pack('<I', 0xBA5EBA11)
    # Reserved bytes in TLV header ( 4 bytes)
    if tlv_type is tlv_type_t.PRIV_KEY:
        key_info_byte = _get_tlv_header_key_info_byte(tlv_type_info)
        reserved_bytes = '000000'
        tlv_header_bytes = reserved_bytes + key_info_byte[2:]
        tlv_header_bytes = int(tlv_header_bytes, 16)
        print(f'TLV header flag bytes = {tlv_header_bytes}')
        tlv_header = tlv_header + struct.pack('<I', tlv_header_bytes)
    else:
        tlv_header = tlv_header + struct.pack('<I', 0x00000000)

    # Add the tlv type ( unsigned short )
    tlv_header = tlv_header + struct.pack('<B', tlv_type)
    tlv_header = tlv_header + struct.pack('<B', tlv_subtype)
    # Add the data_length ( unsigned short )
    tlv_header = tlv_header + struct.pack('<H', data_len)
    tlv = tlv_header + data
    # Add padding after data and before the footer
    padding_len = MIN_ALIGNMENT_REQUIRED - (len(data) % MIN_ALIGNMENT_REQUIRED)

    padding_len = 0 if padding_len == MIN_ALIGNMENT_REQUIRED else padding_len
    tlv = tlv + b'\x00' * padding_len
    # Add the crc value ( unsigned int )
    # The value `0xffffffff` corresponds to the
    # starting value used at the time of calculation
    tlv_footer = struct.pack('<I', zlib.crc32(tlv, 0xffffffff))
    tlv = tlv + tlv_footer
    return tlv


def generate_partition_rsa_ds(ciphertext, iv, efuse_key_id, rsa_key_len,
                              device_cert, ca_cert, op_file):
    # cust_flash partition is of size 0x2000 i.e. 8192 bytes
    tlv_data_length = 0
    with open(op_file, 'wb') as output_file:
        partition_size = 0x2000
        output_file_data = bytearray(b'\xff' * partition_size)
        cur_offset = 0
        dev_cert_data = load_certificate(device_cert)

        # Write dev cert at specific address
        if dev_cert_data["encoding"] == serialization.Encoding.PEM.value:
            dev_cert = dev_cert_data["bytes"] + b'\0'
        else:
            dev_cert = dev_cert_data["bytes"]
        dev_cert_tlv = prepare_tlv(tlv_type_t.DEV_CERT,
                                   0,
                                   None,
                                   dev_cert,
                                   len(dev_cert))
        output_file_data[cur_offset: cur_offset
                         + len(dev_cert_tlv)] = dev_cert_tlv
        cur_offset = cur_offset + len(dev_cert_tlv)
        print('dev_cert tlv: total length = {}'.format(len(dev_cert_tlv)))
        tlv_data_length += len(dev_cert_tlv)

        if ca_cert is not None:
            ca_cert_data = load_certificate(ca_cert)
            # Write dev cert at specific address
            if ca_cert_data["encoding"] == serialization.Encoding.PEM.value:
                ca_cert = ca_cert_data["bytes"] + b'\0'
            else:
                ca_cert = ca_cert_data["bytes"]
            ca_cert_tlv = prepare_tlv(tlv_type_t.CA_CERT,
                                      0,
                                      None,
                                      ca_cert,
                                      len(ca_cert))
            output_file_data[cur_offset: cur_offset
                             + len(ca_cert_tlv)] = ca_cert_tlv
            cur_offset = cur_offset + len(ca_cert_tlv)
            print('ca_cert tlv: total length = {}'
                  .format(len(ca_cert_tlv)))
            tlv_data_length += len(ca_cert_tlv)

        # create esp_secure_cert_data struct
        ds_data = struct.pack('<i', rsa_key_len // 32 - 1)
        ds_data = ds_data + iv
        ds_data = ds_data + ciphertext

        ds_data_tlv = prepare_tlv(tlv_type_t.DS_DATA, 0, None,
                                  ds_data, len(ds_data))
        output_file_data[cur_offset: cur_offset
                         + len(ds_data_tlv)] = ds_data_tlv
        cur_offset = cur_offset + len(ds_data_tlv)
        print('ds_data tlv: total length = {}'.format(len(ds_data_tlv)))
        tlv_data_length += len(ds_data_tlv)

        # create ds_context struct
        ds_context = struct.pack('<I', 0)
        ds_context = ds_context + struct.pack('<B', efuse_key_id)
        # Add padding to match the compiler
        ds_context = ds_context + struct.pack('<B', 0)
        ds_context = ds_context + struct.pack('<H', rsa_key_len)

        ds_context_tlv = prepare_tlv(tlv_type_t.DS_CONTEXT,
                                     0,
                                     None,
                                     ds_context,
                                     len(ds_context))
        output_file_data[cur_offset: cur_offset
                         + len(ds_context_tlv)] = ds_context_tlv
        cur_offset = cur_offset + len(ds_context_tlv)
        print('ds_context tlv: total length = {}'.format(len(ds_context_tlv)))
        tlv_data_length += len(ds_context_tlv)
        print('Total length of tlv data = {}'.format(tlv_data_length))
        output_file.write(output_file_data)
        output_file.close()


def generate_partition_ecdsa(efuse_key_id, device_cert, ca_cert, op_file):
    # cust_flash partition is of size 0x2000 i.e. 8192 bytes
    tlv_data_length = 0
    with open(op_file, 'wb') as output_file:
        partition_size = 0x2000
        output_file_data = bytearray(b'\xff' * partition_size)
        cur_offset = 0
        dev_cert_data = load_certificate(device_cert)

        # Write dev cert at specific address
        if dev_cert_data["encoding"] == serialization.Encoding.PEM.value:
            dev_cert = dev_cert_data["bytes"] + b'\0'
        else:
            dev_cert = dev_cert_data["bytes"]
        dev_cert_tlv = prepare_tlv(tlv_type_t.DEV_CERT,
                                   0,
                                   None,
                                   dev_cert,
                                   len(dev_cert))
        output_file_data[cur_offset: cur_offset
                         + len(dev_cert_tlv)] = dev_cert_tlv
        cur_offset = cur_offset + len(dev_cert_tlv)
        print('dev_cert tlv: total length = {}'.format(len(dev_cert_tlv)))
        tlv_data_length += len(dev_cert_tlv)

        if ca_cert is not None:
            ca_cert_data = load_certificate(ca_cert)
            # Write dev cert at specific address
            if ca_cert_data["encoding"] == serialization.Encoding.PEM.value:
                ca_cert = ca_cert_data["bytes"] + b'\0'
            else:
                ca_cert = ca_cert_data["bytes"]
            ca_cert_tlv = prepare_tlv(tlv_type_t.CA_CERT,
                                      0,
                                      None,
                                      ca_cert,
                                      len(ca_cert))
            output_file_data[cur_offset: cur_offset
                             + len(ca_cert_tlv)] = ca_cert_tlv
            cur_offset = cur_offset + len(ca_cert_tlv)
            print('ca_cert tlv: total length = {}'
                  .format(len(ca_cert_tlv)))
            tlv_data_length += len(ca_cert_tlv)

        # Prepare priv key dummy tlv
        priv_key = bytearray()
        priv_key_tlv = prepare_tlv(tlv_type_t.PRIV_KEY,
                                   0,
                                   tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY,  # type: ignore # noqa: E501
                                   priv_key,
                                   len(priv_key))
        output_file_data[cur_offset: cur_offset
                         + len(priv_key_tlv)] = priv_key_tlv
        cur_offset = cur_offset + len(priv_key_tlv)
        print('ca_cert tlv: total length = {}'
              .format(len(priv_key_tlv)))
        tlv_data_length += len(priv_key_tlv)

        efuse_block_id = efuse_key_id + 4
        sec_cfg = struct.pack('<B', efuse_block_id) + b'\0' * 39
        print(f'length of sec_cfg struct = {len(sec_cfg)}')
        sec_cfg_tlv = prepare_tlv(tlv_type_t.SEC_CFG,
                                  0,
                                  None,
                                  sec_cfg,
                                  len(sec_cfg))

        output_file_data[cur_offset: cur_offset
                         + len(sec_cfg_tlv)] = sec_cfg_tlv

        print(f'sec_cfg tlv: total length = {len(sec_cfg_tlv)}')
        tlv_data_length += len(sec_cfg_tlv)

        print('Total length of tlv data = {}'.format(tlv_data_length))
        output_file.write(output_file_data)
        output_file.close()


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is enabled.
def generate_partition_ds(priv_key: tlv_priv_key_t,
                          device_cert, ca_cert, idf_target, csv_data,
                          op_file):
    if (priv_key.key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_RSA_DS_PERIPHERAL_KEY):  # type: ignore # noqa: E501
        if (priv_key.priv_key_len <= 0 or
                priv_key.efuse_key_id < 0 or
                priv_key.ciphertext is None or
                priv_key.iv is None or
                op_file is None):

            raise ValueError('Invalid arguments')

        generate_partition_rsa_ds(priv_key.ciphertext,
                                  priv_key.iv,
                                  priv_key.efuse_key_id,
                                  priv_key.priv_key_len,
                                  device_cert,
                                  ca_cert,
                                  op_file)

    elif (priv_key.key_type == tlv_priv_key_type_t.ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY):  # type: ignore # noqa: E501
        if (priv_key.priv_key_len <= 0 or
                priv_key.efuse_key_id < 0 or
                op_file is None):
            raise ValueError('Invalid arguments')

        generate_partition_ecdsa(priv_key.efuse_key_id,
                                 device_cert, ca_cert, op_file)

    else:
        raise ValueError('Invalid key type')


def check_tlv_uniqueness(tlv_type, tlv_subtype):

    if (tlv_type, tlv_subtype) in tlv_type_subtype_set:
        raise RuntimeError(f'ERROR: Same TLV type: {tlv_type.name}'
                           ' and TLV subtype: {tlv_subtype} cannot be reused')


def load_data_from_csv_entry(csv_entry):
    tlv_type = tlv_type_t.__members__.get(csv_entry['tlv_type'])
    tlv_data = None
    value = csv_entry['value']
    encoding = csv_entry['content_encoding']
    content_type = csv_entry['content_type']

    cert_types = {tlv_type.CA_CERT, tlv_type.DEV_CERT}
    if tlv_type in cert_types or tlv_type == tlv_type_t.PRIV_KEY:
        if content_type != 'file':
            raise ValueError('Certificate/Key must be given in a file')

        if tlv_type in cert_types:
            data = load_certificate(value)
        else:
            data = load_private_key(value)

        if data["encoding"] == serialization.Encoding.PEM.value:
            tlv_data = data["bytes"] + b'\0'
        else:
            tlv_data = data["bytes"]
        return tlv_data

    else:
        if content_type == 'file':
            with open(value, 'rb') as ip_file:
                tlv_data = ip_file.read()
        elif content_type == 'data':
            if encoding == 'hex2bin':
                value = value.strip()
                tlv_data = binascii.a2b_hex(value)
            elif encoding == 'base64':
                tlv_data = binascii.a2b_base64(value)
            elif encoding == 'string':
                if type(value) == bytes:
                    tlv_data = value.decode()
                tlv_data += '\0'

        return tlv_data


# @info
#       This function generates the cust_flash partition of
#       the encrypted private key parameters when DS is disabled.
def generate_partition_no_ds(priv_key: tlv_priv_key_t,
                             device_cert, ca_cert, idf_target, csv_data,
                             op_file):
    # cust_flash partition is of size 0x2000 i.e. 8192 bytes
    tlv_data_length = 0
    with open(op_file, 'wb') as output_file:
        partition_size = 0x2000
        output_file_data = bytearray(b'\xff' * partition_size)
        cur_offset = 0
        dev_cert_data = load_certificate(device_cert)

        # Write dev cert at specific address
        if dev_cert_data["encoding"] == serialization.Encoding.PEM.value:
            dev_cert = dev_cert_data["bytes"] + b'\0'
        else:
            dev_cert = dev_cert_data["bytes"]
        dev_cert_tlv = prepare_tlv(tlv_type_t.DEV_CERT,
                                   0,
                                   None,
                                   dev_cert,
                                   len(dev_cert))
        output_file_data[cur_offset: cur_offset
                         + len(dev_cert_tlv)] = dev_cert_tlv
        cur_offset = cur_offset + len(dev_cert_tlv)
        print('dev_cert tlv: total length = {}'.format(len(dev_cert_tlv)))
        tlv_data_length += len(dev_cert_tlv)

        if ca_cert is not None:
            ca_cert_data = load_certificate(ca_cert)
            # Write dev cert at specific address
            if ca_cert_data["encoding"] == serialization.Encoding.PEM.value:
                ca_cert = ca_cert_data["bytes"] + b'\0'
            else:
                ca_cert = ca_cert_data["bytes"]
            ca_cert_tlv = prepare_tlv(tlv_type_t.CA_CERT,
                                      0,
                                      None,
                                      ca_cert,
                                      len(ca_cert))
            output_file_data[cur_offset: cur_offset
                             + len(ca_cert_tlv)] = ca_cert_tlv
            cur_offset = cur_offset + len(ca_cert_tlv)
            print('ca_cert tlv: total length = {}'
                  .format(len(ca_cert_tlv)))
            tlv_data_length += len(ca_cert_tlv)

        private_key = []
        if priv_key.key_path is not None:
            private_key_data = load_private_key(priv_key.key_path,
                                                priv_key.key_pass)
            # Write private key at specific address
            if private_key_data["encoding"] == serialization.Encoding.PEM.value:  # type: ignore # noqa: E501
                private_key = private_key_data["bytes"] + b'\0'
            else:
                private_key = private_key_data["bytes"]

        priv_key_tlv = prepare_tlv(tlv_type_t.PRIV_KEY,
                                   0,
                                   priv_key.key_type,
                                   private_key,
                                   len(private_key))

        output_file_data[cur_offset: cur_offset
                         + len(priv_key_tlv)] = priv_key_tlv
        cur_offset = cur_offset + len(priv_key_tlv)

        print('priv_key tlv: total length = {}'.format(len(priv_key_tlv)))
        tlv_data_length += len(priv_key_tlv)

        if csv_data is not None:
            for csv_entry in csv_data:
                tlv_data = load_data_from_csv_entry(csv_entry)
                tlv_type = tlv_type_t.__members__.get(csv_entry['tlv_type'])
                tlv_subtype = int(csv_entry['tlv_subtype'], 10)
                tlv = prepare_tlv(tlv_type,
                                  tlv_subtype,
                                  None,
                                  tlv_data,
                                  len(tlv_data))
                print(f'TLV type: {tlv_type.name}, subtype: {tlv_subtype},'
                      ' total length: {len(tlv_data)}')
                output_file_data[cur_offset: cur_offset + len(tlv)] = tlv
                cur_offset = cur_offset + len(tlv)
                tlv_data_length += len(tlv)

        print('Total length of tlv data = {}'.format(tlv_data_length))
        output_file.write(output_file_data)
        output_file.close()
