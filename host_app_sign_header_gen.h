/**
 * @file    host_app_sign_header_gen.h
 * @brief   Runtime Host App Signed Header generation for HSE secure boot tests.
 *
 * Replaces hardcoded macro arrays (ORDINARY_APP_SIGN_HEADER_NBD, etc.) with
 * a fully dynamic byte-buffer generator replicating old COMET framework
 * behaviour (getappheader / getappheaderBD).
 */

#ifndef HOST_APP_SIGN_HEADER_GEN_H
#define HOST_APP_SIGN_HEADER_GEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "hse_interface.h"
#include "hse_srv_responses.h"

/* =========================================================================
 * Module ID macros
 * ========================================================================= */

#define MOD_ID_HBL_047        ((uint16_t)(0x0047U))
#define MOD_ID_HBL_048        ((uint16_t)(0x0048U))
#define MOD_ID_HBL_049        ((uint16_t)(0x0049U))
#define MOD_ID_APP_SW         ((uint16_t)(0x0051U))
#define MOD_ID_BOOT_UPDATER   ((uint16_t)(0x0052U))
#define MOD_ID_SBAT           ((uint16_t)(0x005BU))
#define MOD_ID_0078           ((uint16_t)(0x0078U))
#define MOD_ID_347D           ((uint16_t)(0x347DU))
#define MOD_ID_6576           ((uint16_t)(0x6576U))
#define MOD_ID_C41A           ((uint16_t)(0xC41AU))
#define MOD_ID_GEN_DATA       ((uint16_t)(0xFD00U))
#define MOD_ID_CIB_B          ((uint16_t)(0xFD80U))
#define MOD_ID_CIB_A          ((uint16_t)(0xFE00U))
#define MOD_ID_MS_RTM         ((uint16_t)(0xFE80U))
#define MOD_ID_ETM            ((uint16_t)(0xFF00U))
#define MOD_ID_UNUSED_FLASH   ((uint16_t)(0xFF80U))
#define MOD_ID_SBIT           ((uint16_t)(0x0001U))

/* =========================================================================
 * Size constants
 * ========================================================================= */

#define HOST_APP_SIGN_HDR_MAX_SIZE        (1024U)
#define HOST_APP_MAX_REGIONS              (8U)
#define HOST_APP_HASH_SIZE                (32U)
#define HOST_APP_SIGNER_INFO_SIZE         (538U)
#define HOST_APP_SIGNATURE_FIELD_SIZE     (256U)
#define HOST_APP_PUBLIC_KEY_FIELD_SIZE    (256U)
#define HOST_APP_ED25519_SIGNATURE_SIZE   (64U)

/* =========================================================================
 * Default byte array macros
 * ========================================================================= */

/** Valid ECU Name: ASCII "TEST_ECU" */
#define HOST_APP_ECU_NAME_VALID \
    {0x54U, 0x45U, 0x53U, 0x54U, 0x5FU, 0x45U, 0x43U, 0x55U}

/** Invalid ECU Name (corrupt byte at index 2 and 3) */
#define HOST_APP_ECU_NAME_INVALID \
    {0x54U, 0x45U, 0x00U, 0x04U, 0x5FU, 0x45U, 0x43U, 0x55U}

/** Default ECU ID (16 bytes) */
#define HOST_APP_ECU_ID_DEFAULT \
    {0x11U, 0x23U, 0x45U, 0xFFU, 0x00U, 0x11U, 0x26U, 0xFFU, \
     0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xF0U, 0xFFU, 0xFFU}

/** Subject Name (16 bytes): "SUBJECT_NAME_V1\0" */
#define HOST_APP_SUBJECT_NAME \
    {0x53U, 0x55U, 0x42U, 0x4AU, 0x45U, 0x43U, 0x54U, 0x5FU, \
     0x4EU, 0x41U, 0x4DU, 0x45U, 0x5FU, 0x56U, 0x31U, 0x00U}

/** Certificate ID (8 bytes) */
#define HOST_APP_CERT_ID \
    {0x00U, 0x03U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U}

/** Key NBID (2 bytes) */
#define HOST_APP_KEY_NBID \
    {0x00U, 0x00U}

/* =========================================================================
 * SBIT layout offsets
 * ========================================================================= */

/** Normal layout: number of modules word offset from SBIT base */
#define SBIT_NORMAL_NUM_MODULES_OFFSET       (62U)
/** Normal layout: first module table entry offset from SBIT base */
#define SBIT_NORMAL_FIRST_MODULE_OFFSET      (64U)

/** MGAL layout: number of modules word offset from SBIT base */
#define SBIT_MGAL_NUM_MODULES_OFFSET         (64U)
/** MGAL layout: first module table entry offset from SBIT base */
#define SBIT_MGAL_FIRST_MODULE_OFFSET        (66U)

/** Bytes per module table entry: 2-byte moduleId + 2-byte moduleInfoOffset */
#define SBIT_MODULE_ENTRY_SIZE               (4U)

/** Bytes per region entry: 4-byte startAddr + 4-byte length + 1-byte vIdIndex */
#define SBIT_REGION_ENTRY_SIZE               (9U)

/** Offset of numberOfRegions inside a module info block */
#define SBIT_MODULE_INFO_REGION_COUNT_OFFSET (2U)

/** Offset of first region entry inside a module info block */
#define SBIT_REGION_START_OFFSET             (3U)

/* =========================================================================
 * Structures
 * ========================================================================= */

/**
 * @brief Describes one SW memory region (start address + byte length).
 */
typedef struct
{
    uint32_t startAddr;
    uint32_t length;
} HostAppRegionInfo_t;

/**
 * @brief Parameters controlling runtime header generation.
 *
 * bitDiffType:
 *   HSE_SB_SIGNED_HDR_NOT_BIT_DIFF_TYPE  → non-bit-diff header (866 bytes base)
 *   HSE_SB_SIGNED_HDR_BIT_DIFF_TYPE      → bit-diff header     (898 bytes base)
 *
 * useSbitForRegion:
 *   1 → parse SBIT using moduleId to obtain region start/length
 *   0 → use explicitRegionStart / explicitRegionLength
 *
 * useInvalidEcuName:
 *   0 → embed HOST_APP_ECU_NAME_VALID  ("TEST_ECU")
 *   1 → embed HOST_APP_ECU_NAME_INVALID
 *
 * useInvalidModuleId:
 *   0 → write moduleId into header Module ID field as-is
 *   1 → write 0xC000 into header Module ID field (SBIT lookup still uses real moduleId)
 *
 * Key pointers:
 *   All four key pointers must point to 32-byte Ed25519 raw key material.
 *   NULL pointers cause GenerateHostAppSignedHeader() to return
 *   HSE_SRV_RSP_GENERAL_ERROR — no random key generation is performed.
 */
typedef struct
{
    /* Identity */
    uint16_t moduleId;
    uint16_t bcid;
    uint16_t appNbid;

    /* Header variant */
    uint8_t  bitDiffType;

    /* Negative-test knobs */
    uint8_t  useInvalidEcuName;
    uint8_t  useInvalidModuleId;

    /* Region source */
    uint8_t  useSbitForRegion;
    uint32_t explicitRegionStart;
    uint32_t explicitRegionLength;

    /* Bit-diff digest inputs (BD path only, must not be NULL/0 when BD) */
    const uint8_t *fullToBeRawData;
    uint32_t       fullToBeRawDataLen;
    const uint8_t *bitDiffEnvelope;
    uint32_t       bitDiffEnvelopeLen;

    /* Ed25519 key material — all four must be non-NULL */
    const uint8_t *rootPrivateKey32;    /**< 32-byte raw private key for Root Signature      */
    const uint8_t *rootPublicKey32;     /**< 32-byte raw public  key written to Signer Info  */
    const uint8_t *signerPrivateKey32;  /**< 32-byte raw private key for Header Signature    */
    const uint8_t *signerPublicKey32;   /**< 32-byte raw public  key written to Signer Info  */

} HostAppSignHeaderGenParams_t;

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * @brief Set the base address of the SBIT image in memory.
 *
 * Must be called before GenerateHostAppSignedHeader() when useSbitForRegion = 1.
 * The address may be unaligned; all SBIT access uses byte-safe helpers.
 *
 * @param sbitBaseAddress  Physical address of the SBIT image.
 */
void HostApp_SetSbitBaseAddress(uint32_t sbitBaseAddress);

/**
 * @brief Parse SBIT and return all regions for a given module ID.
 *
 * @param moduleId    Module to search for.
 * @param regions     Caller-supplied array to receive region descriptors.
 * @param maxRegions  Capacity of the regions array (use HOST_APP_MAX_REGIONS).
 * @param numRegions  Receives the actual number of regions found.
 * @return HSE_SRV_RSP_NO_ERROR on success.
 */
hseSrvResponse_t HostApp_GetRegionsFromSbit(
    uint16_t             moduleId,
    HostAppRegionInfo_t *regions,
    uint16_t             maxRegions,
    uint16_t            *numRegions);

/**
 * @brief Generate a runtime Host App Signed Header byte stream.
 *
 * Replaces the hardcoded ORDINARY_APP_SIGN_HEADER_NBD / _BD macro arrays.
 *
 * @param outHeader       Destination buffer (must be aligned(4)).
 * @param outHeaderMaxLen Byte capacity of outHeader (>= HOST_APP_SIGN_HDR_MAX_SIZE).
 * @param outHeaderLen    Receives the number of bytes written.
 * @param params          Generation parameters; see HostAppSignHeaderGenParams_t.
 * @return HSE_SRV_RSP_NO_ERROR on success, HSE_SRV_RSP_GENERAL_ERROR otherwise.
 */
hseSrvResponse_t GenerateHostAppSignedHeader(
    uint8_t                            *outHeader,
    uint32_t                            outHeaderMaxLen,
    uint32_t                           *outHeaderLen,
    const HostAppSignHeaderGenParams_t *params);

/* =========================================================================
 * wolfSSL crypto helper APIs
 * ========================================================================= */

/**
 * @brief Compute SHA-256 over a contiguous byte buffer.
 *
 * @param data    Input data pointer.
 * @param len     Input data length in bytes.
 * @param outHash 32-byte output buffer.
 */
hseSrvResponse_t HostApp_WolfCryptSha256(
    const uint8_t *data,
    uint32_t       len,
    uint8_t       *outHash);

/**
 * @brief Compute SHA-256 over one or more non-contiguous memory regions.
 *
 * Feeds each region into the same SHA-256 context in order, producing a
 * single digest covering all regions concatenated.
 *
 * @param regions    Array of region descriptors.
 * @param numRegions Number of entries in regions[].
 * @param outHash    32-byte output buffer.
 */
hseSrvResponse_t HostApp_WolfCryptSha256Regions(
    const HostAppRegionInfo_t *regions,
    uint16_t                   numRegions,
    uint8_t                   *outHash);

/**
 * @brief Sign a message with an Ed25519 private key.
 *
 * @param msg          Message buffer to sign.
 * @param msgLen       Length of message in bytes.
 * @param privKey      32-byte Ed25519 private key (raw).
 * @param signatureOut 64-byte output buffer for the raw Ed25519 signature.
 */
hseSrvResponse_t HostApp_WolfCryptEd25519Sign(
    const uint8_t *msg,
    uint32_t       msgLen,
    const uint8_t *privKey,
    uint8_t       *signatureOut);

/**
 * @brief Generate an ephemeral Ed25519 key pair (debug / test use only).
 *
 * WARNING: Do NOT use generated keys for real HSE verification flows.
 *          For production test cases, supply keys via HostAppSignHeaderGenParams_t.
 *
 * @param pubKey   32-byte output buffer for public key.
 * @param privKey  32-byte output buffer for private key.
 */
hseSrvResponse_t HostApp_WolfCryptGenerateEd25519KeyPair(
    uint8_t *pubKey,
    uint8_t *privKey);

/* =========================================================================
 * Debug APIs
 * ========================================================================= */

/**
 * @brief Print field offsets and hex values of a generated header to stdout.
 *
 * @param hdr        Generated header buffer.
 * @param len        Length of generated header in bytes.
 * @param bitDiffType HSE_SB_SIGNED_HDR_NOT_BIT_DIFF_TYPE or _BIT_DIFF_TYPE.
 */
void HostApp_DumpHeaderOffsets(
    const uint8_t *hdr,
    uint32_t       len,
    uint8_t        bitDiffType);

/**
 * @brief Byte-compare a generated header against a golden reference.
 *
 * @param generated    Runtime-generated header.
 * @param generatedLen Length of generated header.
 * @param golden       Reference byte array (e.g. old macro array).
 * @param goldenLen    Length of golden array.
 * @return 0 if identical, -1 if lengths differ, first differing byte offset otherwise.
 */
int HostApp_CompareWithGolden(
    const uint8_t *generated,
    uint32_t       generatedLen,
    const uint8_t *golden,
    uint32_t       goldenLen);

#ifdef __cplusplus
}
#endif

#endif /* HOST_APP_SIGN_HEADER_GEN_H */
