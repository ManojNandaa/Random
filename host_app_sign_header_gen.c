/**
 * @file    host_app_sign_header_gen.c
 * @brief   Runtime Host App Signed Header generation — NXP HSE secure boot test framework.
 *
 * Replicates old COMET framework getappheader() / getappheaderBD() behaviour:
 *
 *   Non-bit-diff (NBD) header layout (n=1, 866 bytes before padding):
 *     [0-1]    Module ID           2 bytes
 *     [2-3]    BCID                2 bytes
 *     [4-11]   ECU Name            8 bytes
 *     [12-27]  ECU ID             16 bytes
 *     [28-29]  App-NBID            2 bytes
 *     [30-31]  Num SW regions      2 bytes
 *     [32-35]  Region start addr   4 bytes
 *     [36-39]  Region length       4 bytes
 *     [40-71]  Message Digest     32 bytes
 *     [72-609] Signer Info       538 bytes
 *     [610-865] Header Signature 256 bytes
 *     [866+]   Alignment padding (to even boundary)
 *
 *   Bit-diff (BD) header layout (n=1, 898 bytes before padding):
 *     [0-1]    Module ID                         2 bytes
 *     [2-33]   Digest of Full To-Be Raw Data     32 bytes
 *     [34-35]  BCID                               2 bytes
 *     [36-43]  ECU Name                           8 bytes
 *     [44-59]  ECU ID                            16 bytes
 *     [60-61]  App-NBID                           2 bytes
 *     [62-63]  Num SW regions                     2 bytes
 *     [64-67]  Region start addr                  4 bytes
 *     [68-71]  Region length                      4 bytes
 *     [72-103] Digest of Bit-diff Envelope       32 bytes
 *     [104-641] Signer Info                      538 bytes
 *     [642-897] Header Signature                 256 bytes
 *     [898+]   Alignment padding (to even boundary)
 *
 *   Signer Info (538 bytes):
 *     Subject Name      16 bytes
 *     Certificate ID     8 bytes
 *     Key-NBID           2 bytes
 *     Signer Public Key 256 bytes  (32-byte Ed25519 key zero-padded to 256)
 *     Root Signature    256 bytes  (64-byte Ed25519 sig zero-padded to 256)
 */

#include "host_app_sign_header_gen.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* =========================================================================
 * Internal constants
 * ========================================================================= */

#define SBIT_MAGIC_BYTE          (0x55U)
#define SBIT_LAYOUT_NORMAL       (0x01U)
#define SBIT_LAYOUT_MGAL_LO      (0x02U)
#define SBIT_LAYOUT_MGAL_HI      (0x03U)

#define ECU_NAME_SIZE            (8U)
#define ECU_ID_SIZE              (16U)
#define SUBJECT_NAME_SIZE        (16U)
#define CERT_ID_SIZE             (8U)
#define KEY_NBID_SIZE            (2U)

/* Ed25519 raw sizes */
#define ED25519_PUBKEY_RAW_SIZE  (32U)
#define ED25519_PRIVKEY_RAW_SIZE (32U)
#define ED25519_SIG_RAW_SIZE     (64U)

/* =========================================================================
 * Module-level SBIT base address
 * ========================================================================= */

static uint32_t s_SbitBaseAddress = 0U;

/* =========================================================================
 * Byte-safe read/write helpers
 *
 * The SBIT base address may be unaligned (e.g. 0x25EFE7CD).
 * Never cast the byte pointer to uint16_t* or uint32_t*.
 * All multi-byte fields in SBIT are big-endian.
 * ========================================================================= */

static uint16_t ReadBe16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]);
}

static uint32_t ReadBe32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U)
         | ((uint32_t)p[1] << 16U)
         | ((uint32_t)p[2] <<  8U)
         |  (uint32_t)p[3];
}

static void WriteBe16(uint8_t *p, uint16_t val)
{
    p[0] = (uint8_t)((val >> 8U) & 0xFFU);
    p[1] = (uint8_t)( val        & 0xFFU);
}

static void WriteBe32(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)((val >> 24U) & 0xFFU);
    p[1] = (uint8_t)((val >> 16U) & 0xFFU);
    p[2] = (uint8_t)((val >>  8U) & 0xFFU);
    p[3] = (uint8_t)( val         & 0xFFU);
}

/**
 * @brief Append src bytes to dst at *offset, advance *offset.
 *
 * @return 0 on success, -1 if buffer would overflow.
 */
static int AppendBytes(uint8_t       *dst,
                       uint32_t       dstMaxLen,
                       uint32_t      *offset,
                       const uint8_t *src,
                       uint32_t       srcLen)
{
    if ((*offset + srcLen) > dstMaxLen)
    {
        return -1;
    }
    (void)memcpy(&dst[*offset], src, (size_t)srcLen);
    *offset += srcLen;
    return 0;
}

/**
 * @brief Append srcLen zero bytes to dst at *offset, advance *offset.
 *
 * @return 0 on success, -1 if buffer would overflow.
 */
static int AppendZeros(uint8_t  *dst,
                       uint32_t  dstMaxLen,
                       uint32_t *offset,
                       uint32_t  count)
{
    if ((*offset + count) > dstMaxLen)
    {
        return -1;
    }
    (void)memset(&dst[*offset], 0x00, (size_t)count);
    *offset += count;
    return 0;
}

/* =========================================================================
 * Public: HostApp_SetSbitBaseAddress
 * ========================================================================= */

void HostApp_SetSbitBaseAddress(uint32_t sbitBaseAddress)
{
    s_SbitBaseAddress = sbitBaseAddress;
}

/* =========================================================================
 * Internal: DetectSbitLayout
 *
 * Checks SBIT magic byte and version byte to determine layout type.
 *
 * @param pSbit            Byte pointer to SBIT base.
 * @param outFirstModOff   Receives offset of first module table entry.
 * @param outNumModOff     Receives offset of the module count word.
 * @return 0 on success, -1 if magic is wrong or layout unrecognised.
 * ========================================================================= */

static int DetectSbitLayout(const uint8_t *pSbit,
                             uint32_t      *outFirstModOff,
                             uint32_t      *outNumModOff)
{
    if (pSbit[0] != SBIT_MAGIC_BYTE)
    {
        return -1;
    }

    switch (pSbit[1])
    {
        case SBIT_LAYOUT_NORMAL:
            *outNumModOff   = SBIT_NORMAL_NUM_MODULES_OFFSET;
            *outFirstModOff = SBIT_NORMAL_FIRST_MODULE_OFFSET;
            break;

        case SBIT_LAYOUT_MGAL_LO:
        case SBIT_LAYOUT_MGAL_HI:
            *outNumModOff   = SBIT_MGAL_NUM_MODULES_OFFSET;
            *outFirstModOff = SBIT_MGAL_FIRST_MODULE_OFFSET;
            break;

        default:
            return -1;
    }

    return 0;
}

/* =========================================================================
 * Public: HostApp_GetRegionsFromSbit
 *
 * Walks the SBIT module table looking for moduleId.
 * When found, reads all region entries from that module's info block.
 *
 * SBIT module table (from firstModOff):
 *   Each entry is SBIT_MODULE_ENTRY_SIZE (4) bytes:
 *     [0-1]  moduleId        (BE uint16)
 *     [2-3]  moduleInfoOff   (BE uint16) — byte offset from SBIT base
 *
 * Module info block (at pSbit + moduleInfoOff):
 *   [0-1]  CCID             (2 bytes, not used here)
 *   [2]    numberOfRegions  (1 byte)
 *   [3+]   region entries   (SBIT_REGION_ENTRY_SIZE = 9 bytes each)
 *
 * Region entry:
 *   [0-3]  startAddress     (BE uint32)
 *   [4-7]  length           (BE uint32)
 *   [8]    vIdIndex         (1 byte, not used here)
 * ========================================================================= */

hseSrvResponse_t HostApp_GetRegionsFromSbit(uint16_t             moduleId,
                                             HostAppRegionInfo_t *regions,
                                             uint16_t             maxRegions,
                                             uint16_t            *numRegions)
{
    const uint8_t *pSbit;
    uint32_t       firstModOff;
    uint32_t       numModOff;
    uint16_t       numModules;
    uint32_t       i;

    if ((regions == NULL) || (numRegions == NULL) || (maxRegions == 0U))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    if (s_SbitBaseAddress == 0U)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* Cast once to byte pointer — all subsequent access is byte-safe */
    pSbit = (const uint8_t *)(uintptr_t)s_SbitBaseAddress;

    if (DetectSbitLayout(pSbit, &firstModOff, &numModOff) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    numModules = ReadBe16(pSbit + numModOff);
    *numRegions = 0U;

    for (i = 0U; i < (uint32_t)numModules; i++)
    {
        const uint8_t *pEntry;
        uint16_t       entryModId;
        uint16_t       modInfoOff;
        const uint8_t *pModInfo;
        uint8_t        regionCount;
        uint16_t       r;

        pEntry     = pSbit + firstModOff + (i * SBIT_MODULE_ENTRY_SIZE);
        entryModId = ReadBe16(pEntry);
        modInfoOff = ReadBe16(pEntry + 2U);

        if (entryModId != moduleId)
        {
            continue;
        }

        /* Found the module — read its region info */
        pModInfo    = pSbit + (uint32_t)modInfoOff;
        regionCount = pModInfo[SBIT_MODULE_INFO_REGION_COUNT_OFFSET];

        for (r = 0U; r < (uint16_t)regionCount; r++)
        {
            const uint8_t *pRegion;

            if (*numRegions >= maxRegions)
            {
                /* Caller buffer full — return what we have */
                break;
            }

            pRegion = pModInfo + SBIT_REGION_START_OFFSET
                      + ((uint32_t)r * SBIT_REGION_ENTRY_SIZE);

            regions[*numRegions].startAddr = ReadBe32(pRegion);
            regions[*numRegions].length    = ReadBe32(pRegion + 4U);
            /* pRegion[8] is vIdIndex — not used in header generation */

            (*numRegions)++;
        }

        return HSE_SRV_RSP_NO_ERROR;
    }

    /* Module ID not found in SBIT */
    return HSE_SRV_RSP_GENERAL_ERROR;
}

/* =========================================================================
 * Public: HostApp_WolfCryptSha256
 * ========================================================================= */

hseSrvResponse_t HostApp_WolfCryptSha256(const uint8_t *data,
                                          uint32_t       len,
                                          uint8_t       *outHash)
{
    wc_Sha256 ctx;
    int        rc;

    if ((data == NULL) || (outHash == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_InitSha256(&ctx);
    if (rc != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_Sha256Update(&ctx, data, (word32)len);
    if (rc != 0)
    {
        wc_Sha256Free(&ctx);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_Sha256Final(&ctx, outHash);
    wc_Sha256Free(&ctx);

    return (rc == 0) ? HSE_SRV_RSP_NO_ERROR : HSE_SRV_RSP_GENERAL_ERROR;
}

/* =========================================================================
 * Public: HostApp_WolfCryptSha256Regions
 *
 * Feeds multiple non-contiguous memory regions into one SHA-256 context,
 * producing a single digest as if the regions were concatenated.
 * This matches old COMET behaviour for multi-region module hashing.
 * ========================================================================= */

hseSrvResponse_t HostApp_WolfCryptSha256Regions(const HostAppRegionInfo_t *regions,
                                                  uint16_t                   numRegions,
                                                  uint8_t                   *outHash)
{
    wc_Sha256  ctx;
    int        rc;
    uint16_t   i;

    if ((regions == NULL) || (numRegions == 0U) || (outHash == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_InitSha256(&ctx);
    if (rc != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    for (i = 0U; i < numRegions; i++)
    {
        const uint8_t *pRegion = (const uint8_t *)(uintptr_t)regions[i].startAddr;

        rc = wc_Sha256Update(&ctx, pRegion, (word32)regions[i].length);
        if (rc != 0)
        {
            wc_Sha256Free(&ctx);
            return HSE_SRV_RSP_GENERAL_ERROR;
        }
    }

    rc = wc_Sha256Final(&ctx, outHash);
    wc_Sha256Free(&ctx);

    return (rc == 0) ? HSE_SRV_RSP_NO_ERROR : HSE_SRV_RSP_GENERAL_ERROR;
}

/* =========================================================================
 * Public: HostApp_WolfCryptEd25519Sign
 *
 * Signs msgLen bytes at msg using the supplied 32-byte Ed25519 private key.
 * Produces a 64-byte raw Ed25519 signature in signatureOut.
 *
 * wc_ed25519_import_private_key() in wolfSSL expects:
 *   privKey  = 32-byte private scalar
 *   pubKey   = 32-byte public key
 * so we derive the public key from private before importing.
 * ========================================================================= */

hseSrvResponse_t HostApp_WolfCryptEd25519Sign(const uint8_t *msg,
                                               uint32_t       msgLen,
                                               const uint8_t *privKey,
                                               uint8_t       *signatureOut)
{
    ed25519_key key;
    word32      sigLen = ED25519_SIG_RAW_SIZE;
    int         rc;
    /* Derive public key from private key for import */
    uint8_t     pubKeyBuf[ED25519_PUBKEY_RAW_SIZE];

    if ((msg == NULL) || (privKey == NULL) || (signatureOut == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_init(&key);
    if (rc != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /*
     * Import private key. wolfSSL's wc_ed25519_import_private_key() requires
     * both the private scalar and the public key. We use wc_ed25519_make_public()
     * to derive the public key from the private scalar.
     */
    rc = wc_ed25519_import_private_only(privKey, ED25519_PRIVKEY_RAW_SIZE, &key);
    if (rc != 0)
    {
        wc_ed25519_free(&key);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* Compute the matching public key so wolfSSL can sign */
    rc = wc_ed25519_make_public(&key, pubKeyBuf, ED25519_PUBKEY_RAW_SIZE);
    if (rc != 0)
    {
        wc_ed25519_free(&key);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_import_private_key(privKey, ED25519_PRIVKEY_RAW_SIZE,
                                        pubKeyBuf, ED25519_PUBKEY_RAW_SIZE,
                                        &key);
    if (rc != 0)
    {
        wc_ed25519_free(&key);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_sign_msg(msg, (word32)msgLen, signatureOut, &sigLen, &key);
    wc_ed25519_free(&key);

    if ((rc != 0) || (sigLen != ED25519_SIG_RAW_SIZE))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    return HSE_SRV_RSP_NO_ERROR;
}

/* =========================================================================
 * Public: HostApp_WolfCryptGenerateEd25519KeyPair
 *
 * Generates an ephemeral Ed25519 key pair for debug/test purposes only.
 *
 * WARNING: Do NOT use random keys for real HSE verification.
 *          Supply fixed keys via HostAppSignHeaderGenParams_t instead.
 * ========================================================================= */

hseSrvResponse_t HostApp_WolfCryptGenerateEd25519KeyPair(uint8_t *pubKey,
                                                           uint8_t *privKey)
{
    WC_RNG    rng;
    ed25519_key key;
    word32    pubKeyLen  = ED25519_PUBKEY_RAW_SIZE;
    word32    privKeyLen = ED25519_PRIVKEY_RAW_SIZE;
    int       rc;

    if ((pubKey == NULL) || (privKey == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_InitRng(&rng);
    if (rc != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_init(&key);
    if (rc != 0)
    {
        (void)wc_FreeRng(&rng);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_make_key(&rng, ED25519_PUBKEY_RAW_SIZE, &key);
    if (rc != 0)
    {
        wc_ed25519_free(&key);
        (void)wc_FreeRng(&rng);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_export_public(&key, pubKey, &pubKeyLen);
    if (rc != 0)
    {
        wc_ed25519_free(&key);
        (void)wc_FreeRng(&rng);
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    rc = wc_ed25519_export_private_only(&key, privKey, &privKeyLen);

    wc_ed25519_free(&key);
    (void)wc_FreeRng(&rng);

    return (rc == 0) ? HSE_SRV_RSP_NO_ERROR : HSE_SRV_RSP_GENERAL_ERROR;
}

/* =========================================================================
 * Internal: Ed25519_PadTo256
 *
 * Copies rawLen bytes from raw into a 256-byte field at dst, then
 * zero-pads the remaining (256 - rawLen) bytes.
 * ========================================================================= */

static void Ed25519_PadTo256(uint8_t       *dst,
                              const uint8_t *raw,
                              uint32_t       rawLen)
{
    (void)memcpy(dst, raw, (size_t)rawLen);
    (void)memset(dst + rawLen, 0x00, (size_t)(HOST_APP_SIGNATURE_FIELD_SIZE - rawLen));
}

/* =========================================================================
 * Internal: BuildRootSignatureInput
 *
 * Constructs the byte buffer that is signed by the root private key to
 * produce the Root Signature embedded in Signer Info.
 *
 * Current construction:
 *   SubjectName[16] || CertificateID[8] || KeyNBID[2] || SignerPublicKey[256]
 *
 * NOTE: This must match the legacy GM/OEM root signature rule exactly.
 *       If the specification defines a different input (e.g. a hash of the
 *       above, or additional fields), update this function accordingly.
 *       The implementation is deliberately isolated here to make that change
 *       easy without touching the rest of the generator.
 *
 * @param outBuf     Destination buffer (must be >= 282 bytes).
 * @param outLen     Receives the number of bytes written.
 * @param subjectName     16-byte subject name.
 * @param certId          8-byte certificate ID.
 * @param keyNbid         2-byte key NBID.
 * @param signerPubKey256 256-byte padded signer public key.
 * ========================================================================= */

#define ROOT_SIG_INPUT_SIZE  (SUBJECT_NAME_SIZE + CERT_ID_SIZE + KEY_NBID_SIZE \
                              + HOST_APP_PUBLIC_KEY_FIELD_SIZE)
/* = 16 + 8 + 2 + 256 = 282 */

static void BuildRootSignatureInput(uint8_t       *outBuf,
                                    uint32_t      *outLen,
                                    const uint8_t *subjectName,
                                    const uint8_t *certId,
                                    const uint8_t *keyNbid,
                                    const uint8_t *signerPubKey256)
{
    uint32_t off = 0U;

    (void)memcpy(outBuf + off, subjectName,    SUBJECT_NAME_SIZE);
    off += SUBJECT_NAME_SIZE;

    (void)memcpy(outBuf + off, certId,         CERT_ID_SIZE);
    off += CERT_ID_SIZE;

    (void)memcpy(outBuf + off, keyNbid,        KEY_NBID_SIZE);
    off += KEY_NBID_SIZE;

    (void)memcpy(outBuf + off, signerPubKey256, HOST_APP_PUBLIC_KEY_FIELD_SIZE);
    off += HOST_APP_PUBLIC_KEY_FIELD_SIZE;

    *outLen = off;
}

/* =========================================================================
 * Internal: BuildSignerInfo
 *
 * Fills the 538-byte Signer Info block at dst[0..537]:
 *
 *   [0-15]    Subject Name      16 bytes
 *   [16-23]   Certificate ID     8 bytes
 *   [24-25]   Key-NBID           2 bytes
 *   [26-281]  Signer Public Key 256 bytes  (32-byte Ed25519, zero-padded)
 *   [282-537] Root Signature    256 bytes  (64-byte Ed25519, zero-padded)
 *
 * @param dst                 Output buffer (must have >= 538 bytes available).
 * @param signerPublicKey32   32-byte Ed25519 signer public key.
 * @param rootPrivateKey32    32-byte Ed25519 root private key (signs the input).
 * @return HSE_SRV_RSP_NO_ERROR on success.
 * ========================================================================= */

static hseSrvResponse_t BuildSignerInfo(uint8_t       *dst,
                                         const uint8_t *signerPublicKey32,
                                         const uint8_t *rootPrivateKey32)
{
    /* Default field values */
    static const uint8_t kSubjectName[SUBJECT_NAME_SIZE] = HOST_APP_SUBJECT_NAME;
    static const uint8_t kCertId[CERT_ID_SIZE]           = HOST_APP_CERT_ID;
    static const uint8_t kKeyNbid[KEY_NBID_SIZE]         = HOST_APP_KEY_NBID;

    /* Signer public key padded to 256 bytes */
    uint8_t signerPubKey256[HOST_APP_PUBLIC_KEY_FIELD_SIZE];

    /* Root signature input and output */
    uint8_t rootSigInput[ROOT_SIG_INPUT_SIZE];
    uint32_t rootSigInputLen = 0U;
    uint8_t rootSigRaw[ED25519_SIG_RAW_SIZE];
    uint8_t rootSig256[HOST_APP_SIGNATURE_FIELD_SIZE];

    hseSrvResponse_t rc;
    uint32_t off = 0U;

    /* 1. Pad signer public key 32 → 256 bytes */
    Ed25519_PadTo256(signerPubKey256, signerPublicKey32, ED25519_PUBKEY_RAW_SIZE);

    /* 2. Build root signature input */
    BuildRootSignatureInput(rootSigInput, &rootSigInputLen,
                            kSubjectName, kCertId, kKeyNbid, signerPubKey256);

    /* 3. Sign with root private key → 64-byte raw signature */
    rc = HostApp_WolfCryptEd25519Sign(rootSigInput, rootSigInputLen,
                                       rootPrivateKey32, rootSigRaw);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }

    /* 4. Pad root signature 64 → 256 bytes */
    Ed25519_PadTo256(rootSig256, rootSigRaw, ED25519_SIG_RAW_SIZE);

    /* 5. Serialise Signer Info into dst */
    (void)memcpy(dst + off, kSubjectName,    SUBJECT_NAME_SIZE);  off += SUBJECT_NAME_SIZE;
    (void)memcpy(dst + off, kCertId,         CERT_ID_SIZE);       off += CERT_ID_SIZE;
    (void)memcpy(dst + off, kKeyNbid,        KEY_NBID_SIZE);      off += KEY_NBID_SIZE;
    (void)memcpy(dst + off, signerPubKey256, HOST_APP_PUBLIC_KEY_FIELD_SIZE);
    off += HOST_APP_PUBLIC_KEY_FIELD_SIZE;
    (void)memcpy(dst + off, rootSig256,      HOST_APP_SIGNATURE_FIELD_SIZE);
    off += HOST_APP_SIGNATURE_FIELD_SIZE;

    /* Confirm we wrote exactly 538 bytes */
    if (off != HOST_APP_SIGNER_INFO_SIZE)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    return HSE_SRV_RSP_NO_ERROR;
}

/* =========================================================================
 * Internal: AppendSwLocationInfo
 *
 * Appends App SW Location Info to dst at *offset:
 *   numSwRegions  2 bytes BE
 *   For each region:
 *     startAddress  4 bytes BE
 *     length        4 bytes BE
 * ========================================================================= */

static int AppendSwLocationInfo(uint8_t                   *dst,
                                 uint32_t                   dstMaxLen,
                                 uint32_t                  *offset,
                                 const HostAppRegionInfo_t *regions,
                                 uint16_t                   numRegions)
{
    uint8_t  tmp2[2];
    uint8_t  tmp4[4];
    uint16_t r;

    /* Number of regions */
    WriteBe16(tmp2, numRegions);
    if (AppendBytes(dst, dstMaxLen, offset, tmp2, 2U) != 0)
    {
        return -1;
    }

    for (r = 0U; r < numRegions; r++)
    {
        WriteBe32(tmp4, regions[r].startAddr);
        if (AppendBytes(dst, dstMaxLen, offset, tmp4, 4U) != 0)
        {
            return -1;
        }

        WriteBe32(tmp4, regions[r].length);
        if (AppendBytes(dst, dstMaxLen, offset, tmp4, 4U) != 0)
        {
            return -1;
        }
    }

    return 0;
}

/* =========================================================================
 * Internal: GenerateNonBitDiffHeader
 *
 * Serialises the non-bit-diff (NBD) header into outHeader[0..].
 * Signs all bytes before the signature field using the signer private key.
 *
 * Layout (n=1):
 *   [0-1]    Module ID         2 BE
 *   [2-3]    BCID              2 BE
 *   [4-11]   ECU Name          8
 *   [12-27]  ECU ID           16
 *   [28-29]  App-NBID          2 BE
 *   [30-39]  SW Location Info 10  (2 + 4 + 4 for n=1)
 *   [40-71]  Message Digest   32
 *   [72-609] Signer Info     538
 *   [610-865] Header Sig     256
 *   [866]    Alignment pad    0 or 1 byte (to even total)
 * ========================================================================= */

static hseSrvResponse_t GenerateNonBitDiffHeader(
        uint8_t                            *outHeader,
        uint32_t                            outHeaderMaxLen,
        uint32_t                           *outHeaderLen,
        const HostAppSignHeaderGenParams_t *params,
        const HostAppRegionInfo_t          *regions,
        uint16_t                            numRegions,
        const uint8_t                      *signerInfoBlock)
{
    static const uint8_t kEcuNameValid[ECU_NAME_SIZE]   = HOST_APP_ECU_NAME_VALID;
    static const uint8_t kEcuNameInvalid[ECU_NAME_SIZE] = HOST_APP_ECU_NAME_INVALID;
    static const uint8_t kEcuId[ECU_ID_SIZE]            = HOST_APP_ECU_ID_DEFAULT;

    const uint8_t *pEcuName;
    uint16_t       moduleIdToWrite;
    uint8_t        tmp2[2];
    uint8_t        tmp4[4];

    uint8_t  msgDigest[HOST_APP_HASH_SIZE];
    uint8_t  sigRaw[ED25519_SIG_RAW_SIZE];
    uint8_t  sig256[HOST_APP_SIGNATURE_FIELD_SIZE];

    uint32_t         off = 0U;
    uint32_t         sigInputLen;
    hseSrvResponse_t rc;

    /* Select ECU Name */
    pEcuName = (params->useInvalidEcuName != 0U) ? kEcuNameInvalid : kEcuNameValid;

    /* Select Module ID to write (negative test may inject 0xC000) */
    moduleIdToWrite = (params->useInvalidModuleId != 0U) ? (uint16_t)0xC000U
                                                          : params->moduleId;

    /* --- 1. Module ID --- */
    WriteBe16(tmp2, moduleIdToWrite);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 2. BCID --- */
    WriteBe16(tmp2, params->bcid);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 3. ECU Name (8 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, pEcuName, ECU_NAME_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 4. ECU ID (16 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, kEcuId, ECU_ID_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 5. App-NBID --- */
    WriteBe16(tmp2, params->appNbid);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 6. App SW Location Info --- */
    if (AppendSwLocationInfo(outHeader, outHeaderMaxLen, &off, regions, numRegions) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 7. Message Digest (SHA-256 over all regions) --- */
    rc = HostApp_WolfCryptSha256Regions(regions, numRegions, msgDigest);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, msgDigest, HOST_APP_HASH_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 8. Signer Info (538 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    signerInfoBlock, HOST_APP_SIGNER_INFO_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 9. Header Signature ---
     * Sign all bytes written so far (offset 0 .. off-1).
     * Then pad Ed25519 64-byte signature to 256 bytes.
     */
    sigInputLen = off;

    rc = HostApp_WolfCryptEd25519Sign(outHeader, sigInputLen,
                                       params->signerPrivateKey32, sigRaw);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }

    Ed25519_PadTo256(sig256, sigRaw, ED25519_SIG_RAW_SIZE);

    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    sig256, HOST_APP_SIGNATURE_FIELD_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 10. Alignment padding — pad to next even byte boundary --- */
    if ((off % 2U) != 0U)
    {
        if (AppendZeros(outHeader, outHeaderMaxLen, &off, 1U) != 0)
        {
            return HSE_SRV_RSP_GENERAL_ERROR;
        }
    }

    *outHeaderLen = off;
    (void)tmp4; /* suppress unused warning if no region path used it */
    return HSE_SRV_RSP_NO_ERROR;
}

/* =========================================================================
 * Internal: GenerateBitDiffHeader
 *
 * Serialises the bit-diff (BD) header into outHeader[0..].
 *
 * Layout (n=1):
 *   [0-1]    Module ID                        2 BE
 *   [2-33]   Digest of Full To-Be Raw Data   32
 *   [34-35]  BCID                             2 BE
 *   [36-43]  ECU Name                         8
 *   [44-59]  ECU ID                          16
 *   [60-61]  App-NBID                         2 BE
 *   [62-71]  SW Location Info               10  (2 + 4 + 4 for n=1)
 *   [72-103] Digest of Bit-diff Envelope     32
 *   [104-641] Signer Info                   538
 *   [642-897] Header Signature              256
 *   [898]    Alignment pad (to even total)
 * ========================================================================= */

static hseSrvResponse_t GenerateBitDiffHeader(
        uint8_t                            *outHeader,
        uint32_t                            outHeaderMaxLen,
        uint32_t                           *outHeaderLen,
        const HostAppSignHeaderGenParams_t *params,
        const HostAppRegionInfo_t          *regions,
        uint16_t                            numRegions,
        const uint8_t                      *signerInfoBlock)
{
    static const uint8_t kEcuNameValid[ECU_NAME_SIZE]   = HOST_APP_ECU_NAME_VALID;
    static const uint8_t kEcuNameInvalid[ECU_NAME_SIZE] = HOST_APP_ECU_NAME_INVALID;
    static const uint8_t kEcuId[ECU_ID_SIZE]            = HOST_APP_ECU_ID_DEFAULT;

    const uint8_t *pEcuName;
    uint16_t       moduleIdToWrite;
    uint8_t        tmp2[2];

    uint8_t  digestFullRaw[HOST_APP_HASH_SIZE];
    uint8_t  digestEnvelope[HOST_APP_HASH_SIZE];
    uint8_t  sigRaw[ED25519_SIG_RAW_SIZE];
    uint8_t  sig256[HOST_APP_SIGNATURE_FIELD_SIZE];

    uint32_t         off = 0U;
    uint32_t         sigInputLen;
    hseSrvResponse_t rc;

    /* Validate BD-specific inputs */
    if ((params->fullToBeRawData == NULL) || (params->fullToBeRawDataLen == 0U) ||
        (params->bitDiffEnvelope == NULL) || (params->bitDiffEnvelopeLen == 0U))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    pEcuName        = (params->useInvalidEcuName  != 0U) ? kEcuNameInvalid : kEcuNameValid;
    moduleIdToWrite = (params->useInvalidModuleId != 0U) ? (uint16_t)0xC000U
                                                          : params->moduleId;

    /* --- 1. Module ID --- */
    WriteBe16(tmp2, moduleIdToWrite);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 2. Message Digest of Full To-Be Raw Data (SHA-256 of caller's buffer) --- */
    rc = HostApp_WolfCryptSha256(params->fullToBeRawData,
                                  params->fullToBeRawDataLen,
                                  digestFullRaw);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }
    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    digestFullRaw, HOST_APP_HASH_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 3. BCID --- */
    WriteBe16(tmp2, params->bcid);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 4. ECU Name (8 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, pEcuName, ECU_NAME_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 5. ECU ID (16 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, kEcuId, ECU_ID_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 6. App-NBID --- */
    WriteBe16(tmp2, params->appNbid);
    if (AppendBytes(outHeader, outHeaderMaxLen, &off, tmp2, 2U) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 7. App SW Location Info --- */
    if (AppendSwLocationInfo(outHeader, outHeaderMaxLen, &off, regions, numRegions) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 8. Message Digest of Bit-difference Envelope --- */
    rc = HostApp_WolfCryptSha256(params->bitDiffEnvelope,
                                  params->bitDiffEnvelopeLen,
                                  digestEnvelope);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }
    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    digestEnvelope, HOST_APP_HASH_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 9. Signer Info (538 bytes) --- */
    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    signerInfoBlock, HOST_APP_SIGNER_INFO_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 10. Header Signature ---
     * Sign all bytes from offset 0 up to (but not including) the signature field.
     */
    sigInputLen = off;

    rc = HostApp_WolfCryptEd25519Sign(outHeader, sigInputLen,
                                       params->signerPrivateKey32, sigRaw);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }

    Ed25519_PadTo256(sig256, sigRaw, ED25519_SIG_RAW_SIZE);

    if (AppendBytes(outHeader, outHeaderMaxLen, &off,
                    sig256, HOST_APP_SIGNATURE_FIELD_SIZE) != 0)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- 11. Alignment padding to even byte boundary --- */
    if ((off % 2U) != 0U)
    {
        if (AppendZeros(outHeader, outHeaderMaxLen, &off, 1U) != 0)
        {
            return HSE_SRV_RSP_GENERAL_ERROR;
        }
    }

    *outHeaderLen = off;
    return HSE_SRV_RSP_NO_ERROR;
}

/* =========================================================================
 * Public: GenerateHostAppSignedHeader
 * ========================================================================= */

hseSrvResponse_t GenerateHostAppSignedHeader(
        uint8_t                            *outHeader,
        uint32_t                            outHeaderMaxLen,
        uint32_t                           *outHeaderLen,
        const HostAppSignHeaderGenParams_t *params)
{
    HostAppRegionInfo_t regions[HOST_APP_MAX_REGIONS];
    uint16_t            numRegions = 0U;
    uint8_t             signerInfoBlock[HOST_APP_SIGNER_INFO_SIZE];
    hseSrvResponse_t    rc;

    /* --- Validate required pointers --- */
    if ((outHeader == NULL) || (outHeaderLen == NULL) || (params == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    if (outHeaderMaxLen < HOST_APP_SIGN_HDR_MAX_SIZE)
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /*
     * Key pointers must always be supplied.
     * Random key generation is NOT performed — if any key pointer is NULL,
     * return an error to force the caller to supply explicit key material.
     */
    if ((params->rootPrivateKey32   == NULL) ||
        (params->rootPublicKey32    == NULL) ||
        (params->signerPrivateKey32 == NULL) ||
        (params->signerPublicKey32  == NULL))
    {
        return HSE_SRV_RSP_GENERAL_ERROR;
    }

    /* --- Zero output buffer --- */
    (void)memset(outHeader, 0x00, (size_t)outHeaderMaxLen);
    *outHeaderLen = 0U;

    /* --- Obtain region info --- */
    if (params->useSbitForRegion != 0U)
    {
        rc = HostApp_GetRegionsFromSbit(params->moduleId,
                                         regions,
                                         HOST_APP_MAX_REGIONS,
                                         &numRegions);
        if (rc != HSE_SRV_RSP_NO_ERROR)
        {
            return rc;
        }

        if (numRegions == 0U)
        {
            return HSE_SRV_RSP_GENERAL_ERROR;
        }
    }
    else
    {
        /* Use caller-supplied explicit region */
        regions[0].startAddr = params->explicitRegionStart;
        regions[0].length    = params->explicitRegionLength;
        numRegions = 1U;

        if (regions[0].length == 0U)
        {
            return HSE_SRV_RSP_GENERAL_ERROR;
        }
    }

    /* --- Build Signer Info block --- */
    rc = BuildSignerInfo(signerInfoBlock,
                          params->signerPublicKey32,
                          params->rootPrivateKey32);
    if (rc != HSE_SRV_RSP_NO_ERROR)
    {
        return rc;
    }

    /* --- Dispatch to NBD or BD path --- */
    if (params->bitDiffType == HSE_SB_SIGNED_HDR_NOT_BIT_DIFF_TYPE)
    {
        rc = GenerateNonBitDiffHeader(outHeader, outHeaderMaxLen, outHeaderLen,
                                       params, regions, numRegions, signerInfoBlock);
    }
    else if (params->bitDiffType == HSE_SB_SIGNED_HDR_BIT_DIFF_TYPE)
    {
        rc = GenerateBitDiffHeader(outHeader, outHeaderMaxLen, outHeaderLen,
                                    params, regions, numRegions, signerInfoBlock);
    }
    else
    {
        rc = HSE_SRV_RSP_GENERAL_ERROR;
    }

    return rc;
}

/* =========================================================================
 * Public: HostApp_DumpHeaderOffsets
 *
 * Prints each field name, byte offset, and hex value to stdout.
 * Useful for visual verification against the spec offset map.
 * ========================================================================= */

void HostApp_DumpHeaderOffsets(const uint8_t *hdr,
                                uint32_t       len,
                                uint8_t        bitDiffType)
{
    uint32_t i;

    if ((hdr == NULL) || (len == 0U))
    {
        printf("[DumpHeader] NULL or zero-length buffer\n");
        return;
    }

    printf("=== Host App Signed Header Dump (%s, %u bytes) ===\n",
           (bitDiffType == HSE_SB_SIGNED_HDR_BIT_DIFF_TYPE) ? "BIT-DIFF" : "NON-BIT-DIFF",
           (unsigned int)len);

    if (bitDiffType == HSE_SB_SIGNED_HDR_NOT_BIT_DIFF_TYPE)
    {
        /* NBD offset map (n=1) */
        printf("[00-01] Module ID          : %02X %02X\n",        hdr[0],  hdr[1]);
        printf("[02-03] BCID               : %02X %02X\n",        hdr[2],  hdr[3]);
        printf("[04-11] ECU Name           : ");
        for (i = 4U;  i < 12U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[12-27] ECU ID             : ");
        for (i = 12U; i < 28U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[28-29] App-NBID           : %02X %02X\n",        hdr[28], hdr[29]);
        printf("[30-31] Num SW Regions     : %02X %02X\n",        hdr[30], hdr[31]);
        printf("[32-35] Region Start Addr  : %02X %02X %02X %02X\n",
               hdr[32], hdr[33], hdr[34], hdr[35]);
        printf("[36-39] Region Length      : %02X %02X %02X %02X\n",
               hdr[36], hdr[37], hdr[38], hdr[39]);
        printf("[40-71] Message Digest     : ");
        for (i = 40U; i < 72U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[72-609] Signer Info       : (538 bytes, first 8:) ");
        for (i = 72U; i < 80U;  i++) printf("%02X ", hdr[i]); printf("...\n");
        printf("[610-865] Header Signature : (256 bytes, first 8:) ");
        for (i = 610U; i < 618U && i < len; i++) printf("%02X ", hdr[i]); printf("...\n");
    }
    else
    {
        /* BD offset map (n=1) */
        printf("[00-01]   Module ID                  : %02X %02X\n",  hdr[0],  hdr[1]);
        printf("[02-33]   Digest Full To-Be Raw Data : ");
        for (i = 2U;  i < 34U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[34-35]   BCID                       : %02X %02X\n",  hdr[34], hdr[35]);
        printf("[36-43]   ECU Name                   : ");
        for (i = 36U; i < 44U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[44-59]   ECU ID                     : ");
        for (i = 44U; i < 60U;  i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[60-61]   App-NBID                   : %02X %02X\n",  hdr[60], hdr[61]);
        printf("[62-63]   Num SW Regions              : %02X %02X\n", hdr[62], hdr[63]);
        printf("[64-67]   Region Start Addr           : %02X %02X %02X %02X\n",
               hdr[64], hdr[65], hdr[66], hdr[67]);
        printf("[68-71]   Region Length               : %02X %02X %02X %02X\n",
               hdr[68], hdr[69], hdr[70], hdr[71]);
        printf("[72-103]  Digest Bit-diff Envelope    : ");
        for (i = 72U; i < 104U; i++) printf("%02X ", hdr[i]); printf("\n");
        printf("[104-641] Signer Info                 : (538 bytes, first 8:) ");
        for (i = 104U; i < 112U; i++) printf("%02X ", hdr[i]); printf("...\n");
        printf("[642-897] Header Signature            : (256 bytes, first 8:) ");
        for (i = 642U; i < 650U && i < len; i++) printf("%02X ", hdr[i]); printf("...\n");
    }

    printf("=== End of Header Dump ===\n");
}

/* =========================================================================
 * Public: HostApp_CompareWithGolden
 *
 * Byte-compares generated header against a golden reference array.
 *
 * Returns:
 *   0                  — identical
 *  -1                  — lengths differ
 *   N (first mismatch) — byte offset of first difference
 * ========================================================================= */

int HostApp_CompareWithGolden(const uint8_t *generated,
                               uint32_t       generatedLen,
                               const uint8_t *golden,
                               uint32_t       goldenLen)
{
    uint32_t i;

    if ((generated == NULL) || (golden == NULL))
    {
        return -1;
    }

    if (generatedLen != goldenLen)
    {
        printf("[CompareWithGolden] Length mismatch: generated=%u, golden=%u\n",
               (unsigned int)generatedLen, (unsigned int)goldenLen);
        return -1;
    }

    for (i = 0U; i < generatedLen; i++)
    {
        if (generated[i] != golden[i])
        {
            printf("[CompareWithGolden] First mismatch at byte %u: "
                   "generated=0x%02X golden=0x%02X\n",
                   (unsigned int)i, generated[i], golden[i]);
            return (int)i;
        }
    }

    printf("[CompareWithGolden] Headers match (%u bytes).\n",
           (unsigned int)generatedLen);
    return 0;
}
