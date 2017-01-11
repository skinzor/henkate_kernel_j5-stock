/**
 * \file LibDevKMApi.h
 * \brief Main API of SKM.
 * \author Dmytro Podgornyi (d.podgornyi@samsung.com)
 * \version 0.1
 * \date Created May 28, 2013
 * \par In Samsung Ukraine R&D Center (SURC) under a contract between
 * \par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine) and
 * \par "Samsung Elecrtronics Co", Ltd (Seoul, Republic of Korea)
 * \par Copyright: (c) Samsung Electronics Co, Ltd 2012. All rights reserved.
 */

#ifndef __LIBDEVKMAPI_H_INCLUDED__
#define __LIBDEVKMAPI_H_INCLUDED__

#include <stdint.h>
#include "CommLayerDataPublic.h"

#ifdef __cplusplus
extern "C" {
#endif

/** generateServiceKey
 *
 * Generate service key pair and its certificate signed by device root key.
 * For QSEE private key and certificate are stored on SFS.
 *
 * keyType: either APCS_KEY or SYMM_KEY
 * keyInfo: pointer to struct KeyInfo (see CommLayerData.h)
 * keyInfoLen: size of keyInfo buffer, must be equal to sizeof(struct KeyInfo)
 * TID: pointer to Trustlet ID
 * TIDLen: size of Trustlet ID
 *
 * note: TID is UUID for MobiCore (16 bytes) and
 *       trustlet name for QSEE (at most 16 symbols)
 *
 * return: NO_ERROR on success, error code otherwise
 */
int generateServiceKey(uint8_t keyType,
                       const uint8_t* keyInfo, uint32_t keyInfoLen,
                       const void* TID, uint32_t TIDLen);

/** generateServiceKeyEx
 *
 * Generate service key pair and its certificate signed by device root key.
 * For QSEE private key and certificate are stored on SFS. Additional argument
 * tlv contains certificate attributes that replace default values.
 *
 * keyType: either APCS_KEY or SYMM_KEY
 * keyInfo: pointer to struct KeyInfo (see CommLayerData.h)
 * keyInfoLen: size of keyInfo buffer, must be equal to sizeof(struct KeyInfo)
 * TID: pointer to Trustlet ID
 * TIDLen: size of Trustlet ID
 * tlv: attributes that replace default values while generation. This tlv
 *      buffer should be made using tlvAdd() API. This argument may be NULL.
 * tlvLen: size of tlv buffer
 *
 * note: TID is UUID for MobiCore (16 bytes) and
 *       trustlet name for QSEE (at most 16 symbols)
 *
 * return: NO_ERROR on success, error code otherwise
 */
int generateServiceKeyEx(uint8_t keyType,
                         const uint8_t* keyInfo, uint32_t keyInfoLen,
                         const void* TID, uint32_t TIDLen,
                         const uint8_t* tlv, uint32_t tlvLen);

/** verifyServiceKey (Only for QSEE)
 *
 * Verify service key pair, service certificate, dev root certificate.
 * For QSEE service key pair is stored on SFS.
 *
 * keyType: either APCS_KEY or SYMM_KEY
 * keyInfo: pointer to struct KeyInfo (see CommLayerData.h)
 * keyInfoLen: size of keyInfo buffer, must be equal to sizeof(struct KeyInfo)
 *
 * return: NO_ERROR on success (key pair and certificates are valid),
 *         error code otherwise
 */
int verifyServiceKey(uint8_t keyType,
                     const uint8_t* keyInfo, uint32_t keyInfoLen);

/** getServiceKeyPath
 *
 * Return path where service key is stored.
 *
 * serviceName: NULL terminated string with service name
 * path: output buffer for path
 * pathLen: size of allocated buffer path
 *
 * return: NO_ERROR on success or error code otherwise.
 */
int getServiceKeyPath(const char* serviceName, char *path, uint32_t pathLen);

/** shareServiceKeyInit
 *
 * Preparing for shareServiceKey call. Must be run before using shareServiceKey
 *
 * return: NO_ERROR on success or error code otherwise.
 */
#ifdef USE_QSEE
int shareServiceKeyInit(void);
#endif

/** shareServiceKeyFinal
 *
 * Releasing resources after using shared ServiceKey. Must be run when
 * encapsulated message is not used anymore.
 *
 * return: NO_ERROR on success or error code otherwise.
 */
#ifdef USE_QSEE
int shareServiceKeyFinal(void);
#endif

/** shareServiceKey
 *
 * Return message encapsulated for particular trustlet
 *
 * serviceName: service name, service key should be previously generated
 * out: output buffer for encapsulated message
 * outLen: size of allocated out buffer and contains sizeof written
 *         encapsulated message after call
 *
 * return: NO_ERROR on success or error code otherwise.
 */
#ifdef USE_QSEE
int shareServiceKey(const char* serviceName, uint8_t* out, uint32_t* outLen);
#endif

/** checkAuthKey
 *
 * Verify device root key pair and device root certificate.
 * For QSEE key pair is stored on SFS.
 *
 * keyType: either APCS_KEY or SYMM_KEY
 *
 * return: NO_ERROR on success (key pair and certificate are valid).
 *         error code otherwise
 */
int checkAuthKey(uint8_t keyType);

/** readKeyUID
 *
 * Read UID field from device root certificate.
 *
 * keyUID: buffer for storing UID string
 * keyUIDLen: size of keyUID buffer allocated by caller
 *
 * return: NO_ERROR on success or error code otherwise. On success keyUID
 *         contains NULL-terminated string.
 */
int readKeyUID(uint8_t* keyUID, uint32_t keyUIDLen);

/** getRootPK
 *
 * Return RSA public key of the Samsung CA certificate. 
 *
 * out: output buffer for public key
 * outLen: before call should contain size of allocated out buffer, after call
 *         contains length of the public key.
 * 
 * Public key has ASN.1 format described in RFC5912:
 * +-------------------------------------------------------------+
 * |      |        | +-----------------------------------------+ |
 * | 0x30 | length | | 0x02 | len | RSA.N | 0x02 | len | RSA.E | |
 * |      |        | +-----------------------------------------+ |
 * +-------------------------------------------------------------+
 *
 * return: NO_ERROR on success or error code otherwise.
 */
int getRootPK(uint8_t *out, uint32_t *outLen);

/** tlvInit
 *
 * Initialize TLV buffer. Must be called before tlvAdd()
 *
 * tlv: buffer to initialize
 * tlvLen: size of allocated tlv buffer
 *
 * return: NO_ERROR on success or error otherwise
 */
int tlvInit(uint8_t *tlv, uint32_t tlvLen);

/** tlvAdd
 *
 * Add new attribute to TLV buffer
 *
 * tlv: initialized tlv buffer
 * tlvLen: size of allocated tlv buffer (maximum size)
 * tag: identifier of attribute
 * value: pointer to value of the attribute. Representation depends on
 *        particular attribute
 * valueLen: size of value buffer
 *
 * return: NO_ERROR on success or error otherwise
 */
int tlvAdd(uint8_t *tlv, uint32_t tlvLen, TlvTag_t tag,
           const void *value, uint32_t valueLen);

/** tlvSize
 *
 * Return actual size of TLV buffer. This size should be passed to
 * generateServiceKeyEx.
 *
 * tlv: buffer initialized by tlvInit and constructed by tlvAdd
 * tlvLen: size of allocated tlv buffer (maximum size)
 *
 * return: actual size of TLV buffer on success or negative error code
 *         otherwise
 */
int tlvSize(uint8_t *tlv, uint32_t tlvLen);

#ifdef __cplusplus
}
#endif

#endif /* __LIBDEVKMAPI_H_INCLUDED__ */
