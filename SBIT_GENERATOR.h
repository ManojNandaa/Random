/**
 * @file    SBIT_GENERATOR.h
 *
 * @brief   Secure Boot Info Table (SBIT) Generator - Deterministic Version
 * @details Provides fully deterministic SBIT generation driven by caller-supplied
 *          configuration tables. No internal random generation is used.
 *          Every field (CCID, VD index, region address, length, stage assignment)
 *          is declared by the caller, ensuring identical output for identical input.
 *
 * @note    Compatible with: Comet Devices (S32N family)
 *          Big-endian field encoding enforced throughout.
 *          Supports SBIT Table Type V1, V2, V3.
 *
 * @addtogroup SBIT_GENERATOR
 * @{
 *
 *==============================================================================
 * Revision History:
 *==============================================================================
 * REV   AUTHOR            DATE         DESCRIPTION OF CHANGE
 * ---   ----------------  ----------   ----------------------------
 * 0.1   saurabh shukla    06/01/2026   Initial Version (random-based)
 * 0.2   refactored        07/05/2026   Deterministic caller-supplied version
 *==============================================================================
 *
 * Copyright 2023-2026 NXP.
 * Licensed under applicable NXP license terms.
 */

#ifndef SBIT_GENERATOR_H
#define SBIT_GENERATOR_H

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 *                              INCLUDE FILES
 *============================================================================*/
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "hse_defs.h"
#include "hse_srv_default_info_block_values.h"

/*==============================================================================
 *                         COMPILE-TIME LIMITS
 *============================================================================*/

/** Maximum number of modules allowed in one SBIT table */
#define SBIT_MAX_MODULES            (60U)

/** Maximum number of regions allowed across all modules */
#define SBIT_MAX_REGIONS            (100U)

/** Maximum number of secure boot stages */
#define SBIT_NUM_STAGES             (3U)

/** Maximum SBIT byte buffer size (matches HSM enforcement limit) */
#define SBIT_BUFFER_SIZE            (2048U)

/** Maximum valid SBIT table length the HSM will accept (V1) */
#define SBIT_MAX_VALID_LENGTH       (1587U)

/** Minimum valid SBIT table length the HSM will accept */
#define SBIT_MIN_VALID_LENGTH       (83U)

/** SHA-256 digest size in bytes */
#define SBIT_SHA256_SIZE            (32U)

/** Size of the MGAL module ID field (present in V2/V3 only) */
#define SBIT_MGAL_MOD_ID_LEN        (2U)

/** Bytes from tableType to tableLength (3 x uint16_t) — used for V1 header copy */
#define SBIT_TABLETYPE_TO_LEN_SIZE  (3U * sizeof(uint16_t))

/*==============================================================================
 *                         SBIT TABLE TYPE CONSTANTS
 *============================================================================*/

/** SBIT Table Type V1 — no MGAL field in header */
#define SBIT_TABLE_TYPE_V1          (uint16_t)(0x0155U)

/** SBIT Table TYPE V2 — includes MGAL module ID offset in header */
#define SBIT_TABLE_TYPE_V2          (uint16_t)(0x0255U)

/** SBIT Table Type V3 — includes MGAL module ID offset in header */
#define SBIT_TABLE_TYPE_V3          (uint16_t)(0x0355U)

/** SBIT structure version (always 0x0001) */
#define SBIT_VERSION                (uint16_t)(0x0001U)

/*==============================================================================
 *                         WELL-KNOWN MODULE ID VALUES
 *          Declare these here so callers reference names, not magic numbers.
 *============================================================================*/

#define MOD_ID_HBL_047              (uint16_t)(0x0047U)
#define MOD_ID_HBL_048              (uint16_t)(0x0048U)
#define MOD_ID_HBL_049              (uint16_t)(0x0049U)
#define MOD_ID_APP_SW               (uint16_t)(0x0051U)
#define MOD_ID_BOOT_UPDATER         (uint16_t)(0x0052U)
#define MOD_ID_SBAT                 (uint16_t)(0x005BU)
#define MOD_ID_0078                 (uint16_t)(0x0078U)
#define MOD_ID_347D                 (uint16_t)(0x347DU)
#define MOD_ID_6576                 (uint16_t)(0x6576U)
#define MOD_ID_C41A                 (uint16_t)(0xC41AU)
#define MOD_ID_GEN_DATA             (uint16_t)(0xFD00U)
#define MOD_ID_CIB_B                (uint16_t)(0xFD80U)
#define MOD_ID_CIB_A                (uint16_t)(0xFE00U)
#define MOD_ID_MTS_RTM              (uint16_t)(0xFE80U)
#define MOD_ID_ETM                  (uint16_t)(0xFF00U)
#define MOD_ID_UNUSED_FLASH         (uint16_t)(0xFF80U)
#define MOD_ID_SBIT                 (uint16_t)(0x0001U)

/*==============================================================================
 *                         WELL-KNOWN ADDRESS CONSTANTS
 *          Declared here so getSbitModuleInfo logic can reference them cleanly.
 *          Actual values come from hse_srv_default_info_block_values.h
 *============================================================================*/

#define SBIT_ADDR_HBL               (uint32_t)(0x25C02000UL)
#define SBIT_LEN_HBL                (uint32_t)(0x00000380UL)

#define SBIT_ADDR_MOD_C41A          (uint32_t)(0x25C05000UL)
#define SBIT_LEN_MOD_C41A           (uint32_t)(0x00000178UL)

#define SBIT_ADDR_CIB_A             (uint32_t)(DEFAULT_CIB_A_ADDR)
#define SBIT_LEN_CIB_A              (uint32_t)(CIB_SIZE)

#define SBIT_ADDR_CIB_B             (uint32_t)(DEFAULT_CIB_B_ADDR)
#define SBIT_LEN_CIB_B              (uint32_t)(CIB_SIZE)

/** Sentinel: caller sets startAddr to this to indicate "address not applicable" */
#define SBIT_ADDR_INVALID           (uint32_t)(0xFFFFFFFFUL)

/** Default R1 MAC address (no R1 MAC stored) */
#define SBIT_R1_MAC_ADDR_DEFAULT    (uint32_t)(0xFFFFFFFFUL)

/*==============================================================================
 *                         ENDIANNESS HELPERS
 *============================================================================*/

#define SBIT_SWAP16(x)  \
    (uint16_t)(((uint16_t)(x) >> 8U) | ((uint16_t)(x) << 8U))

#define SBIT_SWAP32(x)  \
    (uint32_t)(  (((uint32_t)(x) & 0x000000FFUL) << 24U) \
               | (((uint32_t)(x) & 0x0000FF00UL) <<  8U) \
               | (((uint32_t)(x) & 0x00FF0000UL) >>  8U) \
               | (((uint32_t)(x) & 0xFF000000UL) >> 24U) )

/*==============================================================================
 *                         LAYOUT SIZE MACROS
 *   These mirror the original macros but are renamed for clarity.
 *   All sizes are in bytes.
 *============================================================================*/

/** Size of one Module Location by ID entry (ModuleID[2] + Offset[2]) */
#define SBIT_MODULE_LOC_ENTRY_SIZE      (4U)

/** Total size of the Module Location table */
#define SBIT_MODULE_LOC_TABLE_SIZE(nMod) \
    ((uint16_t)((nMod) * SBIT_MODULE_LOC_ENTRY_SIZE))

/**
 * Total size of one Stage-X Region Location block:
 *   1 byte  numRegions
 *   2 bytes per region offset
 */
#define SBIT_STAGE_REGION_LOC_SIZE(nRgn) \
    ((uint16_t)(1U + 2U * (nRgn)))

/** Total size of all three stage region location blocks */
#define SBIT_ALL_STAGES_LOC_SIZE(nRgn) \
    ((uint16_t)(3U + 2U * (nRgn)))

/**
 * Size of one Module Info block for module index k (0-based)
 * with regionsBeforeK regions having already been accounted for:
 *   2 bytes CCID
 *   1 byte  numRegions
 *   9 bytes per region (4 startAddr + 4 length + 1 VDindex)
 */
#define SBIT_REGION_INFO_SIZE           (9U)
#define SBIT_MODULE_INFO_HDR_SIZE       (3U)   /* CCID[2] + numRegions[1] */

/** Size of all region info entries for a given region count */
#define SBIT_REGION_INFO_BLOCK_SIZE(nRgn) \
    ((uint16_t)((nRgn) * SBIT_REGION_INFO_SIZE))

/** Size of one complete Module Info entry (header + all its regions) */
#define SBIT_MODULE_INFO_SIZE(nRgn) \
    ((uint16_t)(SBIT_MODULE_INFO_HDR_SIZE + SBIT_REGION_INFO_BLOCK_SIZE(nRgn)))

/**
 * Total SBIT table length:
 *   sbitHeaderSize + ModuleLocTable + AllStagesLoc + sum(ModuleInfo for each module)
 * The macro below computes this for the uniform case (same nRgn across all modules).
 * For non-uniform use sbit_computeTableLength() at runtime.
 */
#define SBIT_TOTAL_LENGTH_UNIFORM(hdrSz, nMod, nRgn) \
    ((uint16_t)( (hdrSz)                              \
               + SBIT_MODULE_LOC_TABLE_SIZE(nMod)     \
               + SBIT_ALL_STAGES_LOC_SIZE(nRgn)       \
               + (nMod) * SBIT_MODULE_INFO_SIZE(nRgn) ))

/*==============================================================================
 *                         STAGE FAILED ACTION VALUES
 *============================================================================*/
typedef enum
{
    SBIT_ACTION_NONE                        = (uint8_t)0U,
    SBIT_ACTION_LOCK_IVN_MAC_GEN            = (uint8_t)1U,
    SBIT_ACTION_LOCK_IVN_MAC_GEN_AND_VER    = (uint8_t)2U,
    SBIT_ACTION_MCU_RESET                   = (uint8_t)3U,
    SBIT_ACTION_INVALID                     = (uint8_t)5U
} Sbit_StageFailedAction_t;

/*==============================================================================
 *                         R1 AUTO VERIFICATION VALUES
 *============================================================================*/
typedef enum
{
    SBIT_R1_AUTO_VERIF_DISABLED  = (uint8_t)0x00U,
    SBIT_R1_AUTO_VERIF_ENABLED   = (uint8_t)0x01U,
    SBIT_R1_AUTO_VERIF_INVALID   = (uint8_t)0xFFU
} Sbit_R1AutoVerif_t;

/*==============================================================================
 *                    INVALID PARAMETER INJECTION FLAGS
 *   Used by test callers to deliberately corrupt one field.
 *   Set to SBIT_INJECT_NONE for normal (valid) generation.
 *============================================================================*/
typedef enum
{
    SBIT_INJECT_NONE            = 0,   /**< No corruption — normal valid SBIT  */
    SBIT_INJECT_TABLE_LENGTH,          /**< Override tableLength with invalidVal */
    SBIT_INJECT_SBIT_VERSION,          /**< Override sbitVersion with invalidVal */
    SBIT_INJECT_NUM_MODULES,           /**< Override numberOfModules            */
    SBIT_INJECT_ZERO_REGIONS,          /**< Set all stage region counts to 0    */
    SBIT_INJECT_BOOT_MSG_DIGEST,       /**< Skip boot message digest calculation */
    SBIT_INJECT_INVALID_REGION_ADDR,   /**< Corrupt last-1 region start address */
    SBIT_INJECT_LARGE_MOD_LENGTH,      /**< Set region length > 1KB for a module*/
    SBIT_INJECT_R1_IN_STAGE2,          /**< Place VD=1 in stage 2 (not stage 1) */
    SBIT_INJECT_R1_IN_STAGE3,          /**< Place VD=1 in stage 3 (not stage 1) */
    SBIT_INJECT_INVALID_VD_S1,         /**< Corrupt VD index of stage 1 region  */
    SBIT_INJECT_INVALID_VD_S2,         /**< Corrupt VD index of stage 2 region  */
    SBIT_INJECT_INVALID_VD_S3,         /**< Corrupt VD index of stage 3 region  */
    SBIT_INJECT_FIXED_HBL_ADDR,        /**< Use alternate HBL start address     */
    SBIT_INJECT_CCID_ZERO              /**< Set CCID of unused-flash module to 0*/
} Sbit_InjectParam_t;

/*==============================================================================
 *                         VERIFICATION TYPE
 *============================================================================*/
typedef enum
{
    SBIT_VERIF_SHA256   = (uint8_t)1U,
    SBIT_VERIF_MAC      = (uint8_t)2U
} Sbit_VerifType_t;

/*==============================================================================
 *                    PER-REGION CONFIGURATION (caller-supplied)
 *
 *  The caller fills one of these per region within a module.
 *  Every field is used directly — no internal randomisation.
 *============================================================================*/
typedef struct
{
    uint32_t startAddr;     /**< Region start address in host code flash        */
    uint32_t length;        /**< Region length in bytes                         */
    uint8_t  vdIndex;       /**< Secure Boot Verification Data index (1-based)  */
    uint8_t  stage;         /**< Stage this region belongs to: 1, 2, or 3       */
} Sbit_RegionCfg_t;

/*==============================================================================
 *                    PER-MODULE CONFIGURATION (caller-supplied)
 *
 *  The caller fills one of these per module.
 *  regions[] must be populated in the order they appear within this module.
 *  numRegions must equal the number of valid entries in regions[].
 *============================================================================*/
typedef struct
{
    uint16_t        moduleId;                       /**< Module ID (big-endian stored by generator) */
    uint16_t        ccid;                           /**< Calibration/Compatibility ID               */
    uint8_t         numRegions;                     /**< Number of regions in this module (1..N)    */
    Sbit_RegionCfg_t regions[SBIT_MAX_REGIONS];    /**< Region descriptors, index 0..numRegions-1  */
} Sbit_ModuleCfg_t;

/*==============================================================================
 *                    TOP-LEVEL SBIT CONFIGURATION (caller-supplied)
 *
 *  This is the single struct the caller populates and passes to
 *  SBIT_Generate(). It completely describes the desired SBIT.
 *  No field inside SBIT_Generate() is derived from rand().
 *============================================================================*/
typedef struct
{
    /* ---- Header fields -------------------------------------------------- */
    uint16_t            tableType;          /**< SBIT_TABLE_TYPE_V1/V2/V3       */
    uint8_t             unusedUpdateFlag;   /**< Unused region update flag       */
    uint8_t             mtsUpdateFlag;      /**< MTS update flag                 */
    uint8_t             cibUpdateFlag;      /**< CIB update flag                 */
    uint8_t             bootUpdateFlag;     /**< Boot update flag                */
    uint8_t             r1AutoVerif;        /**< R1 auto verification flag        */
    uint8_t             stage2FailAction;   /**< Action on Stage 2 failure        */
    uint8_t             stage3FailAction;   /**< Action on Stage 3 failure        */
    uint8_t             fillByte;           /**< Fill byte value (e.g. 0xA5)     */
    uint16_t            hostReqResetTimeout;/**< Watchdog timeout (0 = disabled) */
    uint32_t            macSbitAddr;        /**< MAC SBIT address                 */
    uint32_t            macR1Addr;          /**< MAC R1 address                   */

    /* ---- MGAL (V2/V3 only) ---------------------------------------------- */
    uint16_t            mgalModuleId;       /**< MGAL module ID (0 if unused)    */

    /* ---- Boot message digest -------------------------------------------- */
    uint8_t             bootMsgDigest[SBIT_SHA256_SIZE]; /**< Pre-computed SHA-256
                                                 over host bootloader region.
                                                 If all-zero, generator will
                                                 compute it via HSM call.       */

    /* ---- Module table --------------------------------------------------- */
    uint16_t            numModules;         /**< Number of entries in modules[]  */
    Sbit_ModuleCfg_t    modules[SBIT_MAX_MODULES]; /**< Per-module descriptors  */

    /* ---- Fault injection (test use only) -------------------------------- */
    Sbit_InjectParam_t  injectFlag;         /**< Which field to corrupt (if any) */
    uint16_t            injectValue;        /**< Value to inject                 */

} Sbit_Config_t;

/*==============================================================================
 *                    INTERNAL PACKED STRUCTURES
 *   These map directly onto the SBIT byte array.
 *   All multi-byte fields stored big-endian.
 *============================================================================*/

/** One entry in the Module Location by ID table */
typedef struct __attribute__((packed))
{
    uint16_t moduleId;              /**< Module ID              (big-endian) */
    uint16_t moduleRegionsOffset;   /**< Byte offset to ModuleInfo (big-endian) */
} Sbit_ModuleLocEntry_t;

/** One region info entry within a Module Info block */
typedef struct __attribute__((packed))
{
    uint32_t regionStartAddress;        /**< Start address   (big-endian) */
    uint32_t lengthOfRegion;            /**< Length in bytes (big-endian) */
    uint8_t  sbVerificationDataIndex;   /**< VD index        (no swap needed) */
} Sbit_RegionInfoEntry_t;

/** SBIT main header — V1 layout (no mgalModuleIdOffset field written) */
typedef struct __attribute__((packed))
{
    uint16_t tableType;             /**< Table type                  (big-endian) */
    uint16_t sbitVersion;           /**< SBIT version                (big-endian) */
    uint16_t tableLength;           /**< Total table length          (big-endian) */
    uint16_t mgalModuleIdOffset;    /**< MGAL offset (V2/V3 only)   (big-endian) */
    uint8_t  unusedRegionUpdateFlag;
    uint8_t  mtsUpdateFlag;
    uint8_t  cibUpdateFlag;
    uint8_t  bootUpdateFlag;
    uint8_t  bootMessageDigest[SBIT_SHA256_SIZE];
    uint8_t  r1AutoVerification;
    uint8_t  stage2FailedAction;
    uint8_t  stage3FailedAction;
    uint8_t  fillByteValue;
    uint16_t hostReqResetTimeout;   /**< (big-endian) */
    uint32_t macSbitAddress;        /**< (big-endian) */
    uint32_t macR1Address;          /**< (big-endian) */
    uint16_t stage1InfoOffset;      /**< (big-endian) */
    uint16_t stage2InfoOffset;      /**< (big-endian) */
    uint16_t stage3InfoOffset;      /**< (big-endian) */
    uint16_t numberOfModules;       /**< (big-endian) */
} Sbit_Header_t;

/*==============================================================================
 *                         RETURN CODES
 *============================================================================*/
typedef enum
{
    SBIT_OK                     = 0,
    SBIT_ERR_NULL_PTR,              /**< NULL pointer passed                    */
    SBIT_ERR_TOO_MANY_MODULES,      /**< numModules > SBIT_MAX_MODULES          */
    SBIT_ERR_TOO_MANY_REGIONS,      /**< total regions > SBIT_MAX_REGIONS       */
    SBIT_ERR_TABLE_TOO_LARGE,       /**< computed length > SBIT_MAX_VALID_LENGTH*/
    SBIT_ERR_TABLE_TOO_SMALL,       /**< computed length < SBIT_MIN_VALID_LENGTH*/
    SBIT_ERR_INVALID_STAGE,         /**< region.stage not in {1,2,3}            */
    SBIT_ERR_NO_REGIONS_IN_MODULE,  /**< a module has numRegions == 0           */
    SBIT_ERR_DIGEST_COMPUTE_FAILED, /**< HSM SHA-256 call returned error        */
    SBIT_ERR_INVALID_TABLE_TYPE     /**< tableType not V1/V2/V3                 */
} Sbit_Status_t;

/*==============================================================================
 *                         GLOBAL BUFFER
 *   The generated SBIT byte array. Written by SBIT_Generate().
 *   Exposed so callers can inspect or transmit it.
 *============================================================================*/
extern uint8_t g_sbitBuffer[SBIT_BUFFER_SIZE];

/*==============================================================================
 *                    PUBLIC API
 *============================================================================*/

/**
 * @brief   Generate a complete SBIT byte array from caller-supplied config.
 *
 * @details Produces a fully deterministic, big-endian encoded SBIT in
 *          g_sbitBuffer[] and writes it to DEFAULT_SBIT_AUX_ADDRESS.
 *          The function never calls rand(). Every field value comes from cfg.
 *
 * @param[in]  cfg   Pointer to fully populated Sbit_Config_t. Must not be NULL.
 *
 * @return  SBIT_OK on success, or an Sbit_Status_t error code.
 */
Sbit_Status_t SBIT_Generate(const Sbit_Config_t *cfg);

/**
 * @brief   Compute total SBIT table length from a populated config.
 *
 * @details Does not generate any data. Useful for pre-validation.
 *
 * @param[in]  cfg         Pointer to config.
 * @param[out] outLength   Computed byte length written here.
 *
 * @return  SBIT_OK or error code.
 */
Sbit_Status_t SBIT_ComputeTableLength(const Sbit_Config_t *cfg,
                                      uint16_t            *outLength);

/**
 * @brief   Validate a populated Sbit_Config_t before generation.
 *
 * @details Checks module count, region count, stage assignments,
 *          table length bounds. Does not write any data.
 *
 * @param[in]  cfg   Pointer to config.
 *
 * @return  SBIT_OK if valid, or first error found.
 */
Sbit_Status_t SBIT_ValidateConfig(const Sbit_Config_t *cfg);

/**
 * @brief   Compute SHA-256 boot message digest over HBL region via HSM.
 *
 * @details Finds the module matching hblModuleId inside cfg, locates its
 *          first region, sends a HSE_SRV_ID_HASH request, and writes the
 *          32-byte result into outDigest[].
 *
 * @param[in]  cfg           Pointer to config (modules must be populated).
 * @param[in]  hblModuleId   Module ID to use as HBL source.
 * @param[out] outDigest     32-byte buffer to receive the SHA-256 result.
 *
 * @return  SBIT_OK or SBIT_ERR_DIGEST_COMPUTE_FAILED.
 */
Sbit_Status_t SBIT_ComputeBootDigest(const Sbit_Config_t *cfg,
                                     uint16_t             hblModuleId,
                                     uint8_t              outDigest[SBIT_SHA256_SIZE]);

/**
 * @brief   Write a byte array to a target memory address.
 *
 * @details Wraps memcpy to destination. Separate from SBIT_Generate() so
 *          callers can redirect output (e.g. to a cohort address).
 *
 * @param[in]  destAddr   Target address (e.g. DEFAULT_SBIT_AUX_ADDRESS).
 * @param[in]  pData      Source buffer.
 * @param[in]  length     Number of bytes to copy.
 */
void SBIT_WriteToMemory(uint32_t        destAddr,
                        const uint8_t  *pData,
                        uint32_t        length);

#ifdef __cplusplus
}
#endif

#endif /* SBIT_GENERATOR_H */
/** @} */
