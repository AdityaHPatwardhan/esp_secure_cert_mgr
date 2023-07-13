import os
from typing import Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    load_pem_x509_certificate,
    load_der_x509_certificate
)


def load_private_key(key_file_path: str,
                     password: str = None) -> Dict[str, str]:
    """
    Load a private key from a file in either PEM or DER format.

    Args:
        key_file_path (str): Path to the private key file.
        password (str): Password to decrypt the private key,
                        if it is encrypted.
    Returns:
        Dict[str, str]: A dictionary with the `"encoding"` and `"bytes"` keys.
        The `"encoding"` key holds a value
        of type `str` (a member of the `serialization.Encoding` enum)
        and the `"bytes"` key holds a value of type `bytes`.

    Raises:
        FileNotFoundError: If the private key file cannot be found or read.
        ValueError: If the private key file is not in PEM or DER format.

    """
    result = {}

    try:
        with open(key_file_path, "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Key file not found: {key_file_path}")

    try:
        # Attempt to load the key as a PEM-encoded private key
        private_key = serialization.load_pem_private_key(
                key,
                password=password,
                backend=default_backend())

        result["encoding"] = serialization.Encoding.PEM.value
        key_encoding = serialization.Encoding.PEM
        key_enc_alg = serialization.NoEncryption()
        priv_key_format = serialization.PrivateFormat.TraditionalOpenSSL

        result["bytes"] = private_key.private_bytes(
            encoding=key_encoding,
            format=priv_key_format,
            encryption_algorithm=key_enc_alg
        )
        result["key_instance"] = private_key
        return result
    except ValueError:
        pass

    try:
        private_key = serialization.load_der_private_key(
            key,
            password=password,
            backend=default_backend()
        )
        result["encoding"] = serialization.Encoding.DER.value
        key_encoding = serialization.Encoding.DER
        priv_key_format = serialization.PrivateFormat.TraditionalOpenSSL
        key_enc_alg = serialization.NoEncryption()
        result["bytes"] = private_key.private_bytes(
            encoding=key_encoding,
            format=priv_key_format,
            encryption_algorithm=key_enc_alg
        )
        result["key_instance"] = private_key
        return result
    except ValueError:
        raise ValueError("Unsupported key encoding format,"
                         " Please provide PEM or DER encoded key")


def load_certificate(cert_file_path: str) -> Dict[str, str]:
    """
    Load a certificate from a file in either PEM or DER format.

    Args:
        cert_file_path (str): The path to the certificate file.

    Returns:
        Dict[str, str]: A dictionary with the `"encoding"` and `"bytes"` keys.
        The `"encoding"` key holds a value of
        type `str` (a member of the `serialization.Encoding enum)
        and the `"bytes"` key holds a value of type `bytes`.

    Raises:
        FileNotFoundError: If the certificate file cannot be found or read.
        ValueError: If the certificate file is not in PEM or DER format.
    """
    result = {}

    try:
        with open(cert_file_path, "rb") as cert_file:
            cert_data = cert_file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Cert file not found: {cert_file_path}")

    try:
        cert = load_pem_x509_certificate(cert_data, backend=default_backend())
        result["encoding"] = serialization.Encoding.PEM.value
        cert_encoding = serialization.Encoding.PEM
        result["bytes"] = cert.public_bytes(encoding=cert_encoding)
        result["cert_instance"] = cert
        return result
    except ValueError:
        pass

    try:
        cert = load_der_x509_certificate(cert_data, backend=default_backend())
        result["encoding"] = serialization.Encoding.DER.value
        cert_encoding = serialization.Encoding.DER
        result["bytes"] = cert.public_bytes(encoding=cert_encoding)
        result["cert_instance"] = cert
        return result
    except ValueError:
        raise ValueError("Unsupported certificate encoding format,"
                         "Please provide PEM or DER encoded certificate")


def validate_csv_data(csv_data):
    from . import tlv_format
    for row in csv_data:
        tlv_type = tlv_format.tlv_type_t.__members__.get(row['tlv_type'])
        if tlv_type is None:
            raise ValueError(f'{row["tlv_type"]} is not a valid TLV type')

        tlv_subtype = int(row['tlv_subtype'], 10)
        if (tlv_subtype >= 256):
            raise ValueError(f'TLV subtype: {tlv_subtype} cannot exceed 256')
        elif (tlv_subtype < 0):
            raise ValueError(f'TLV subtype: {tlv_subtype} cannot be negative')

        content_type = row['content_type']
        supported_ext = {'.bin', '.pem', '.der', '.crt', '.key'}
        supported_encoding = {'base64', 'string', 'hex2bin'}
        if content_type == 'file':
            key_file_name, ext = os.path.splitext(row['value'])
            if ext not in supported_ext:
                raise ValueError('The given file type'
                                 f' is not supported: {row["value"]}')

        elif content_type == 'data':
            if row['content_encoding'] not in supported_encoding:
                raise ValueError('The given encoding '
                                 f'{row["content_encoding"]} is not supported')

            if row['content_encoding'] == 'hex2bin':
                value = row['value'].strip()
                if len(value) % 2 != 0:
                    raise ValueError('Invalid data length.'
                                     ' Should be multiple of 2.')
        else:
            raise ValueError(f'Content type {content_type} is not supported')
