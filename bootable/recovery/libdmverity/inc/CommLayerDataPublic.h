/**
* \file CommLayerDataPublic.h
* \brief Public defines and types. Distributes with API.
* \author Dmytro Podgornyi (d.podgornyi@samsung.com)
* \version 0.1
* \date Created Nov 21, 2013
* \par In Samsung Ukraine R&D Center (SURC) under a contract between
* \par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine) and
* \par "Samsung Elecrtronics Co", Ltd (Seoul, Republic of Korea)
* \par Copyright: (c) Samsung Electronics Co, Ltd 2012. All rights reserved.
**/

#ifndef __COMMLAYERDATAPUBLIC_H_INCLUDED__
#define __COMMLAYERDATAPUBLIC_H_INCLUDED__

#include <stdint.h>


//// Key Blob field tags
#define RSA_CERT_TAG      (uint8_t) 0x01
#define IV_TAG            (uint8_t) 0x02
#define KEY_TAG           (uint8_t) 0x03
#define TL_NAME_TAG       (uint8_t) 0x04
#define ATTRS_TAG         (uint8_t) 0x05

//// ERROR CODES
#define NO_ERROR                            			 0
#define UNSUPPORTED_CMD                     ( int32_t ) -1
#define WRONG_DATA                          ( int32_t ) -2
#define PLATFORM_INTERNAL_ERROR             ( int32_t ) -3
#define SHA256_ERROR                        ( int32_t ) -4
#define HMAC_ERROR                          ( int32_t ) -5
#define FS_READ_ERROR                       ( int32_t ) -6
#define WRONG_RSA_CERT                      ( int32_t ) -7
#define WRONG_PRIV_KEY                      ( int32_t ) -8
#define NO_KEY_ERROR                        ( int32_t ) -9
#define WRITE_KEY_ERROR                     ( int32_t ) -10
#define READ_KEY_ERROR                      ( int32_t ) -11
#define WRITE_SYMM_KEY_ERROR                ( int32_t ) -12
#define INSTALL_SYMM_KEY_ERROR              ( int32_t ) -14
#define NO_SYMM_KEY_ERROR                   ( int32_t ) -15 // be reserved by libseckeyprov.so
#define DECRYPT_PROV_ERROR                  ( int32_t ) -16
#define COPY_PROV_ERROR                     ( int32_t ) -17
#define LOCK_FILE_FAIL_ERROR                ( int32_t ) -18
#define PERMISSION_DENIED                   ( int32_t ) -19
#define TLV_WRITE_ERROR                     ( int32_t ) -20
#define SKM_DAEMON_ERROR                    ( int32_t ) -21
#define BUFFER_OVERFLOW                     ( int32_t ) -22
#define TIME_UNAVAILABLE_ERROR              ( int32_t ) -23
#define TA_LOAD_ERROR                       ( int32_t ) -24
#define TA_UNLOAD_ERROR                     ( int32_t ) -25
#define TA_CONNECT_ERROR                    ( int32_t ) -26
#define BASE64_ERROR                        ( int32_t ) -27
#define FS_WRITE_ERROR                      ( int32_t ) -28
#define FS_GENERAL_ERROR                    ( int32_t ) -29
#define SERVICE_NAME_INVALID                ( int32_t ) -30
#define SERVICE_NAME_WRONG                  ( int32_t ) -31
#define SYSPROP_READ_ERROR                  ( int32_t ) -32
#define SEC_ALLOC_ERROR                     ( int32_t ) -33
#define SHA1_ERROR                          ( int32_t ) -34
#define KEK_PARSE_ERROR                     ( int32_t ) -35
#define ASN1_GEN_ERROR                      ( int32_t ) -36
#define CERT_SIGN_ERROR                     ( int32_t ) -37
#define RSA_GEN_ERROR                       ( int32_t ) -38
#define EC_GEN_ERROR                        ( int32_t ) -39
#define QSEE_ENCAP_ERROR                    ( int32_t ) -40
#define RSA_PARSE_ERROR                     ( int32_t ) -41
#define SIGNATURE_INVALID_ERROR             ( int32_t ) -42
#define WRONG_SERVICE_CERT_TYPE             ( int32_t ) -43
#define MEM_ALLOC_ERROR                     ( int32_t ) -41
#define SOCKET_INVALID                      ( int32_t ) -42
#define SOCKET_SEND_FAILED                  ( int32_t ) -43
#define SOCKET_RECV_FAILED                  ( int32_t ) -44


#define REMOVE_DRK_ERROR                    ( int32_t ) -50
#define KEY_SIZE_ERROR                      ( int32_t ) -57
#define TZBSP_SECURE_STATE_CHECK_ERROR      ( int32_t ) -58

#define TZ_KDF_ERROR                        ( int32_t ) -60
#define TZ_RNG_ERROR                        ( int32_t ) -61
#define TZ_CRYPTO_ENC_ERROR                 ( int32_t ) -62
#define TZ_CRYPTO_DEC_ERROR                 ( int32_t ) -63
#define TZ_CRYPTO_WRONG_TAG_ERROR           ( int32_t ) -64
#define TZ_CRYPTO_INIT_ERROR                ( int32_t ) -65

#define NOT_IMPLEMENTED                     ( int32_t ) -127

//// KEY TYPES
typedef enum
{
    /* RSA key */
    RSA_KEY = 0x10,
    /* Symmetric key */
    SYMM_KEY = 0x20,
    /* Elliptic key */
    EC_SK_KEY = 0x40,
    /* EC key */
    ECC_KEY = 0x80,
} ProvAgentKeys_t;

//// Key Info struct
/* UID can be bigger than 52 bytes */
#define MAX_UID_SIZE (52 * 2)
#define MAX_SERVICE_NAME 8
#define MAX_SERIALNO_SIZE 32
#define MAX_MODEL_SIZE 32
#define MAX_DATE_SIZE 16
#define MAX_TID_SIZE 128
#define MAX_TID_SIZE_16 16

typedef enum CertType
{
    CERT_TYPE_NONE = 0,
    CERT_TYPE_RSA
} CertType_t;

struct KeyInfo
{
    /* 52 is for backward compatibility
     * size of KeyInfo must be equal to the old value */
    uint8_t serviceName[52];
    /* device serial number */
    uint8_t serialno[MAX_SERIALNO_SIZE];
    /* model name, ex: SGH-I337 */
    uint8_t model[MAX_MODEL_SIZE];
    /* date */
    uint16_t year;
    uint8_t mon;
    uint8_t mday;
    uint8_t hour;
    uint8_t min;
    uint8_t sec;
    /* key length in bits, default 2048 */
    uint32_t keyLen;
    /* 1 - crt rsa, 0 - without crt */
    CertType_t crt;
};


typedef enum
{
    TLV_EXPONENT = 1,
    TLV_ISSUER,
    TLV_HASH_ALGO,
    TLV_SUBJECT,
    TLV_KEYUSAGE,
    TLV_EXT_KEYUSAGE,
    TLV_SIGN_DATA_BLOB,
    TLV_CERT_SM,
    TLV_CERT_SD,
    TLV_TIMESTAMP,
    TLV_WRAPPED_PCR,
    TLV_EXTEND_PCR_DATA,
    TLV_TID,
    TLV_WRAPPED_KEY,
    TLV_KEY_INFO,
    TLV_ATTRS,
    /* Identifier of the start of a TLV buffer */
    TLV_START = 0xfe
} TlvTag_t;

#endif /* __COMMLAYERDATAPUBLIC_H_INCLUDED__ */
