/**
 * @file    SBIT_GENERATOR.c
 *
 * @brief   Secure Boot Info Table (SBIT) Generator - Deterministic Version
 * @details Implements fully deterministic SBIT generation.
 *          No rand() calls. Every value comes from the caller-supplied
 *          Sbit_Config_t. Identical config always produces identical output.
 *
 * @note    Big-endian encoding enforced for all multi-byte fields per CYS2320.
 *          Supports Table Type V1 (no MGAL), V2 and V3 (with MGAL offset).
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

#include "SBIT_GENERATOR.h"
#include "hse_interface.h"
#include "mu.h"

/*==============================================================================
 *                         GLOBAL BUFFER
 *============================================================================*/

/** The generated SBIT byte array. Zero-initialised at startup. */
uint8_t g_sbitBuffer[SBIT_BUFFER_SIZE] = {0U};

/*==============================================================================
 *                    PRIVATE HELPER: Header size
 *
 *  V1: mgalModuleIdOffset field is NOT written to the buffer.
 *      So the "active" header size is sizeof(Sbit_Header_t) - 2.
 *  V2/V3: full Sbit_Header_t is written.
 *============================================================================*/
static uint8_t prv_HeaderSize(uint16_t tableType)
{
    if (tableType == SBIT_TABLE_TYPE_V1)
    {
        return (uint8_t)(sizeof(Sbit_Header_t) - SBIT_MGAL_MOD_ID_LEN);
    }
    return (uint8_t)(sizeof(Sbit_Header_t));
}

/*==============================================================================
 *                    PRIVATE HELPER: Total region count
 *============================================================================*/
static uint16_t prv_TotalRegions(const Sbit_Config_t *cfg)
{
    uint16_t total = 0U;
    uint16_t m;
    for (m = 0U; m < cfg->numModules; m++)
    {
        total += (uint16_t)cfg->modules[m].numRegions;
    }
    return total;
}

/*==============================================================================
 *                    PRIVATE HELPER: Stage region counts
 *
 *  Counts how many regions across all modules are assigned to stage 1, 2, 3.
 *  Output: stageCounts[0]=S1 count, [1]=S2, [2]=S3.
 *============================================================================*/
static void prv_CountStageRegions(const Sbit_Config_t *cfg,
                                  uint8_t              stageCounts[SBIT_NUM_STAGES])
{
    uint16_t m, r;
    stageCounts[0] = 0U;
    stageCounts[1] = 0U;
    stageCounts[2] = 0U;

    for (m = 0U; m < cfg->numModules; m++)
    {
        for (r = 0U; r < cfg->modules[m].numRegions; r++)
        {
            uint8_t s = cfg->modules[m].regions[r].stage;
            if ((s >= 1U) && (s <= 3U))
            {
                stageCounts[s - 1U]++;
            }
        }
    }
}

/*==============================================================================
 *                    PUBLIC: SBIT_ValidateConfig
 *============================================================================*/
Sbit_Status_t SBIT_ValidateConfig(const Sbit_Config_t *cfg)
{
    uint16_t totalRegions;
    uint16_t tableLength;
    uint16_t m, r;

    if (cfg == NULL)
    {
        return SBIT_ERR_NULL_PTR;
    }

    /* Table type check */
    if ((cfg->tableType != SBIT_TABLE_TYPE_V1) &&
        (cfg->tableType != SBIT_TABLE_TYPE_V2) &&
        (cfg->tableType != SBIT_TABLE_TYPE_V3))
    {
        return SBIT_ERR_INVALID_TABLE_TYPE;
    }

    /* Module count */
    if (cfg->numModules > SBIT_MAX_MODULES)
    {
        return SBIT_ERR_TOO_MANY_MODULES;
    }

    /* Per-module checks */
    totalRegions = 0U;
    for (m = 0U; m < cfg->numModules; m++)
    {
        if (cfg->modules[m].numRegions == 0U)
        {
            return SBIT_ERR_NO_REGIONS_IN_MODULE;
        }

        for (r = 0U; r < cfg->modules[m].numRegions; r++)
        {
            uint8_t stage = cfg->modules[m].regions[r].stage;
            if ((stage < 1U) || (stage > 3U))
            {
                return SBIT_ERR_INVALID_STAGE;
            }
        }

        totalRegions += (uint16_t)cfg->modules[m].numRegions;
    }

    if (totalRegions > SBIT_MAX_REGIONS)
    {
        return SBIT_ERR_TOO_MANY_REGIONS;
    }

    /* Table length bounds (only for non-injected configs) */
    if (cfg->injectFlag == SBIT_INJECT_NONE)
    {
        Sbit_Status_t st = SBIT_ComputeTableLength(cfg, &tableLength);
        if (st != SBIT_OK)
        {
            return st;
        }
        if (tableLength > SBIT_MAX_VALID_LENGTH)
        {
            return SBIT_ERR_TABLE_TOO_LARGE;
        }
        if (tableLength < SBIT_MIN_VALID_LENGTH)
        {
            return SBIT_ERR_TABLE_TOO_SMALL;
        }
    }

    return SBIT_OK;
}

/*==============================================================================
 *                    PUBLIC: SBIT_ComputeTableLength
 *============================================================================*/
Sbit_Status_t SBIT_ComputeTableLength(const Sbit_Config_t *cfg,
                                      uint16_t            *outLength)
{
    uint16_t m;
    uint16_t totalRegions;
    uint8_t  hdrSize;
    uint16_t moduleInfoTotal;

    if ((cfg == NULL) || (outLength == NULL))
    {
        return SBIT_ERR_NULL_PTR;
    }

    hdrSize      = prv_HeaderSize(cfg->tableType);
    totalRegions = prv_TotalRegions(cfg);

    /*
     * Layout:
     *   Header
     *   Module Location by ID table  : numModules * 4
     *   Stage Region Location blocks : 3 + 2*totalRegions
     *   Module Info blocks           : sum over modules of (3 + 9*numRegions)
     */
    moduleInfoTotal = 0U;
    for (m = 0U; m < cfg->numModules; m++)
    {
        moduleInfoTotal += (uint16_t)(SBIT_MODULE_INFO_HDR_SIZE +
                           SBIT_REGION_INFO_BLOCK_SIZE(cfg->modules[m].numRegions));
    }

    *outLength = (uint16_t)(hdrSize
                 + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                 + SBIT_ALL_STAGES_LOC_SIZE(totalRegions)
                 + moduleInfoTotal);

    return SBIT_OK;
}

/*==============================================================================
 *                    PUBLIC: SBIT_ComputeBootDigest
 *============================================================================*/
Sbit_Status_t SBIT_ComputeBootDigest(const Sbit_Config_t *cfg,
                                     uint16_t             hblModuleId,
                                     uint8_t              outDigest[SBIT_SHA256_SIZE])
{
    uint16_t m;
    uint32_t hblAddr   = 0U;
    uint32_t hblLength = 0U;
    bool     found     = false;

    if ((cfg == NULL) || (outDigest == NULL))
    {
        return SBIT_ERR_NULL_PTR;
    }

    /* Find the HBL module and extract its first region */
    for (m = 0U; m < cfg->numModules; m++)
    {
        if (cfg->modules[m].moduleId == hblModuleId)
        {
            hblAddr   = cfg->modules[m].regions[0].startAddr;
            hblLength = cfg->modules[m].regions[0].length;
            found     = true;
            break;
        }
    }

    if (!found)
    {
        return SBIT_ERR_DIGEST_COMPUTE_FAILED;
    }

    /* Issue SHA-256 hash request to HSM via MU */
    {
        hseSrvDescriptor_t hseDesc;
        hseSrvResponse_t   hseResp;
        uint8_t            hashBuf[SBIT_SHA256_SIZE];

        memset(&hseDesc, 0,       sizeof(hseDesc));
        memset(&hashBuf, 0,       sizeof(hashBuf));
        memset(outDigest, 0,      SBIT_SHA256_SIZE);

        hseDesc.srvId                         = HSE_SRV_ID_HASH;
        hseDesc.hseSrv.hashReq.accessMode     = HSE_ACCESS_MODE_ONE_PASS;
        hseDesc.hseSrv.hashReq.hashAlgo       = HSE_HASH_ALGO_SHA2_256;
        hseDesc.hseSrv.hashReq.sgtOption      = HSE_SGT_OPTION_NONE;
        hseDesc.hseSrv.hashReq.inputLength    = hblLength;
        hseDesc.hseSrv.hashReq.pInput         = translate(hblAddr);
        hseDesc.hseSrv.hashReq.hashLength     = SBIT_SHA256_SIZE;
        hseDesc.hseSrv.hashReq.pHash          = translate(hashBuf);

        MU_Send(MU_INST_ID, MU_CH_ID, (HOST_ADDR)&hseDesc);
        hseResp = Wait_MU_Recieve(MU_INST_ID, MU_CH_ID);

        if (hseResp != HSE_SRV_RSP_OK)
        {
            return SBIT_ERR_DIGEST_COMPUTE_FAILED;
        }

        memcpy(outDigest, hashBuf, SBIT_SHA256_SIZE);
    }

    return SBIT_OK;
}

/*==============================================================================
 *                    PUBLIC: SBIT_WriteToMemory
 *============================================================================*/
void SBIT_WriteToMemory(uint32_t       destAddr,
                        const uint8_t *pData,
                        uint32_t       length)
{
    memcpy((void *)(uintptr_t)destAddr, pData, (size_t)length);
}

/*==============================================================================
 *                    PRIVATE: Write Module Location by ID table
 *
 *  Layout written at offset = hdrSize:
 *    For each module i:
 *      [2 bytes] moduleId        (big-endian)
 *      [2 bytes] moduleInfoOffset (big-endian)
 *
 *  moduleInfoOffset for module i points to the start of that module's
 *  Module Info block (CCID + numRegions + region entries).
 *
 *  Base of Module Info section:
 *    hdrSize + ModuleLocTable + AllStagesLoc
 *
 *  Module i's offset within Module Info section:
 *    sum of ModuleInfo sizes for modules 0..(i-1)
 *============================================================================*/
static void prv_WriteModuleLocTable(const Sbit_Config_t *cfg,
                                    uint8_t              hdrSize,
                                    uint16_t             totalRegions)
{
    uint16_t m;
    uint16_t moduleInfoBase;
    uint16_t runningOffset;

    /*
     * Module Info section starts right after:
     *   header + module loc table + all stage region loc blocks
     */
    moduleInfoBase = (uint16_t)(hdrSize
                                + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                                + SBIT_ALL_STAGES_LOC_SIZE(totalRegions));

    runningOffset = moduleInfoBase;

    for (m = 0U; m < cfg->numModules; m++)
    {
        Sbit_ModuleLocEntry_t entry;
        uint16_t              writePos;

        entry.moduleId            = SBIT_SWAP16(cfg->modules[m].moduleId);
        entry.moduleRegionsOffset = SBIT_SWAP16(runningOffset);

        /* Write at: hdrSize + m * sizeof(entry) */
        writePos = (uint16_t)(hdrSize + (m * (uint16_t)sizeof(Sbit_ModuleLocEntry_t)));

        memcpy(&g_sbitBuffer[writePos], &entry, sizeof(entry));

        /* Advance by this module's full Module Info block size */
        runningOffset += (uint16_t)(SBIT_MODULE_INFO_HDR_SIZE +
                         SBIT_REGION_INFO_BLOCK_SIZE(cfg->modules[m].numRegions));
    }
}

/*==============================================================================
 *                    PRIVATE: Write Stage Region Location blocks
 *
 *  Three consecutive blocks at offset = hdrSize + ModuleLocTableSize:
 *
 *  Block for stage X:
 *    [1 byte]  numRegions in stage X
 *    [2 bytes] offset to region info entry, per region in stage X (big-endian)
 *
 *  The offsets point into the Module Info section — specifically to the
 *  start of each Sbit_RegionInfoEntry_t that belongs to stage X.
 *
 *  Walk all modules, all regions; for each region, note its stage and
 *  compute its absolute byte offset within g_sbitBuffer.
 *============================================================================*/
static void prv_WriteStageRegionLocBlocks(const Sbit_Config_t *cfg,
                                          uint8_t              hdrSize,
                                          uint16_t             totalRegions)
{
    /*
     * For each of the 3 stages we collect up to SBIT_MAX_REGIONS offsets.
     * We use fixed-size arrays; actual usage is bounded by totalRegions.
     */
    uint16_t stageOffsets[SBIT_NUM_STAGES][SBIT_MAX_REGIONS];
    uint8_t  stageCounts[SBIT_NUM_STAGES];
    uint16_t m, r;
    uint16_t moduleInfoBase;
    uint16_t moduleRunOffset;  /* running byte offset into module info section */
    uint16_t writePos;

    memset(stageOffsets, 0, sizeof(stageOffsets));
    stageCounts[0] = 0U;
    stageCounts[1] = 0U;
    stageCounts[2] = 0U;

    moduleInfoBase = (uint16_t)(hdrSize
                                + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                                + SBIT_ALL_STAGES_LOC_SIZE(totalRegions));

    moduleRunOffset = moduleInfoBase;

    for (m = 0U; m < cfg->numModules; m++)
    {
        /* Skip CCID (2) + numRegions (1) at start of each Module Info block */
        uint16_t regionRunOffset = (uint16_t)(moduleRunOffset + SBIT_MODULE_INFO_HDR_SIZE);

        for (r = 0U; r < cfg->modules[m].numRegions; r++)
        {
            uint8_t stage = cfg->modules[m].regions[r].stage;

            if ((stage >= 1U) && (stage <= 3U))
            {
                uint8_t si = stage - 1U;
                stageOffsets[si][stageCounts[si]] = regionRunOffset;
                stageCounts[si]++;
            }

            /* Each region entry is 9 bytes */
            regionRunOffset += (uint16_t)SBIT_REGION_INFO_SIZE;
        }

        /* Advance moduleRunOffset past this module's full block */
        moduleRunOffset += (uint16_t)(SBIT_MODULE_INFO_HDR_SIZE +
                           SBIT_REGION_INFO_BLOCK_SIZE(cfg->modules[m].numRegions));
    }

    /*
     * Write the three stage blocks sequentially.
     * Block start = hdrSize + ModuleLocTableSize
     */
    writePos = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));

    {
        uint8_t  si;
        uint8_t  ri;

        for (si = 0U; si < SBIT_NUM_STAGES; si++)
        {
            /* Write count byte */
            g_sbitBuffer[writePos] = stageCounts[si];
            writePos++;

            /* Write each offset (big-endian) */
            for (ri = 0U; ri < stageCounts[si]; ri++)
            {
                uint16_t beOffset = SBIT_SWAP16(stageOffsets[si][ri]);
                memcpy(&g_sbitBuffer[writePos], &beOffset, sizeof(uint16_t));
                writePos += (uint16_t)sizeof(uint16_t);
            }
        }
    }
}

/*==============================================================================
 *                    PRIVATE: Write Module Info blocks
 *
 *  For each module, starting at moduleInfoBase:
 *    [2 bytes] CCID             (big-endian)
 *    [1 byte]  numRegions
 *    For each region:
 *      [4 bytes] startAddress   (big-endian)
 *      [4 bytes] length         (big-endian)
 *      [1 byte]  vdIndex
 *
 *  Fault injection for region address / large length applied here.
 *============================================================================*/
static void prv_WriteModuleInfoBlocks(const Sbit_Config_t *cfg,
                                      uint8_t              hdrSize,
                                      uint16_t             totalRegions)
{
    uint16_t m;
    uint16_t writePos;

    writePos = (uint16_t)(hdrSize
                          + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                          + SBIT_ALL_STAGES_LOC_SIZE(totalRegions));

    for (m = 0U; m < cfg->numModules; m++)
    {
        uint16_t beCcid;
        uint8_t  r;

        /* --- CCID (2 bytes, big-endian) --- */
        beCcid = SBIT_SWAP16(cfg->modules[m].ccid);
        memcpy(&g_sbitBuffer[writePos], &beCcid, sizeof(uint16_t));
        writePos += (uint16_t)sizeof(uint16_t);

        /* --- numRegions (1 byte) --- */
        g_sbitBuffer[writePos] = cfg->modules[m].numRegions;
        writePos++;

        /* --- Region entries --- */
        for (r = 0U; r < cfg->modules[m].numRegions; r++)
        {
            Sbit_RegionInfoEntry_t entry;
            uint32_t               startAddr = cfg->modules[m].regions[r].startAddr;
            uint32_t               length    = cfg->modules[m].regions[r].length;
            uint8_t                vdIdx     = cfg->modules[m].regions[r].vdIndex;

            /* Fault injection: corrupt second-to-last region address */
            if ((cfg->injectFlag == SBIT_INJECT_INVALID_REGION_ADDR) &&
                (m == (cfg->numModules - 1U)) &&
                (r == (cfg->modules[m].numRegions - 2U)))
            {
                startAddr = SBIT_ADDR_INVALID;
            }

            /* Fault injection: large module length on region 0 of target module */
            if ((cfg->injectFlag == SBIT_INJECT_LARGE_MOD_LENGTH) &&
                (cfg->modules[m].moduleId == cfg->injectValue) &&
                (r == 0U))
            {
                length = 1024U + 1U;
            }

            entry.regionStartAddress      = SBIT_SWAP32(startAddr);
            entry.lengthOfRegion          = SBIT_SWAP32(length);
            entry.sbVerificationDataIndex = vdIdx;

            memcpy(&g_sbitBuffer[writePos], &entry, sizeof(entry));
            writePos += (uint16_t)sizeof(entry);
        }
    }
}

/*==============================================================================
 *                    PRIVATE: Write SBIT Header
 *
 *  Fills the Sbit_Header_t struct with big-endian values and copies it
 *  into g_sbitBuffer[0].
 *
 *  For V1: the mgalModuleIdOffset field is skipped (not written).
 *          We copy [tableType..tableLength] first (6 bytes), then the rest
 *          of the struct starting at unusedRegionUpdateFlag.
 *
 *  For V2/V3: the full struct is copied including mgalModuleIdOffset.
 *============================================================================*/
static void prv_WriteHeader(const Sbit_Config_t *cfg,
                            uint8_t              hdrSize,
                            uint16_t             tableLength,
                            uint16_t             stage1Offset,
                            uint16_t             stage2Offset,
                            uint16_t             stage3Offset,
                            const uint8_t        bootDigest[SBIT_SHA256_SIZE])
{
    Sbit_Header_t hdr;
    uint16_t      totalRegions = prv_TotalRegions(cfg);
    uint16_t      mgalOffset;

    memset(&hdr, 0, sizeof(hdr));

    hdr.tableType             = SBIT_SWAP16(cfg->tableType);
    hdr.sbitVersion           = SBIT_SWAP16(SBIT_VERSION);
    hdr.tableLength           = SBIT_SWAP16(tableLength);
    hdr.unusedRegionUpdateFlag = cfg->unusedUpdateFlag;
    hdr.mtsUpdateFlag         = cfg->mtsUpdateFlag;
    hdr.cibUpdateFlag         = cfg->cibUpdateFlag;
    hdr.bootUpdateFlag        = cfg->bootUpdateFlag;
    hdr.r1AutoVerification    = cfg->r1AutoVerif;
    hdr.stage2FailedAction    = cfg->stage2FailAction;
    hdr.stage3FailedAction    = cfg->stage3FailAction;
    hdr.fillByteValue         = cfg->fillByte;
    hdr.hostReqResetTimeout   = SBIT_SWAP16(cfg->hostReqResetTimeout);
    hdr.macSbitAddress        = SBIT_SWAP32(cfg->macSbitAddr);
    hdr.macR1Address          = SBIT_SWAP32(cfg->macR1Addr);
    hdr.stage1InfoOffset      = SBIT_SWAP16(stage1Offset);
    hdr.stage2InfoOffset      = SBIT_SWAP16(stage2Offset);
    hdr.stage3InfoOffset      = SBIT_SWAP16(stage3Offset);
    hdr.numberOfModules       = SBIT_SWAP16(cfg->numModules);

    memcpy(hdr.bootMessageDigest, bootDigest, SBIT_SHA256_SIZE);

    /* V2/V3: MGAL offset points to the byte immediately after the normal table */
    if (cfg->tableType != SBIT_TABLE_TYPE_V1)
    {
        mgalOffset = (uint16_t)(hdrSize
                                + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                                + SBIT_ALL_STAGES_LOC_SIZE(totalRegions));

        /* For each module, add its module info size */
        {
            uint16_t m;
            for (m = 0U; m < cfg->numModules; m++)
            {
                mgalOffset += (uint16_t)(SBIT_MODULE_INFO_HDR_SIZE +
                               SBIT_REGION_INFO_BLOCK_SIZE(cfg->modules[m].numRegions));
            }
        }

        if (cfg->mgalModuleId != 0U)
        {
            /* +4: 2 bytes mgalModId + 2 bytes mgal pointer */
            hdr.tableLength = SBIT_SWAP16(tableLength + SBIT_MGAL_MOD_ID_LEN + 4U);
        }

        hdr.mgalModuleIdOffset = SBIT_SWAP16(mgalOffset);
    }

    /* Copy header into buffer */
    if (cfg->tableType == SBIT_TABLE_TYPE_V1)
    {
        /*
         * V1: Skip mgalModuleIdOffset (offset 6 in struct, 2 bytes).
         * Copy [tableType, sbitVersion, tableLength] first (bytes 0..5),
         * then copy from unusedRegionUpdateFlag onward.
         */
        memcpy(&g_sbitBuffer[0],
               &hdr,
               SBIT_TABLETYPE_TO_LEN_SIZE);   /* 6 bytes: type+version+length */

        memcpy(&g_sbitBuffer[SBIT_TABLETYPE_TO_LEN_SIZE],
               &hdr.unusedRegionUpdateFlag,
               sizeof(Sbit_Header_t) - SBIT_TABLETYPE_TO_LEN_SIZE - SBIT_MGAL_MOD_ID_LEN);
    }
    else
    {
        memcpy(&g_sbitBuffer[0], &hdr, sizeof(Sbit_Header_t));
    }
}

/*==============================================================================
 *                    PRIVATE: Apply fault injection overrides
 *
 *  Called after all sections are written.
 *  Overwrites specific fields in g_sbitBuffer[] with corrupted values.
 *  Fields that are overridden during section generation (region addr, large len)
 *  are handled inline in prv_WriteModuleInfoBlocks() — not repeated here.
 *============================================================================*/
static void prv_ApplyInjection(const Sbit_Config_t *cfg,
                               uint8_t              hdrSize,
                               uint16_t             totalRegions,
                               uint8_t              stageCounts[SBIT_NUM_STAGES])
{
    uint16_t beVal;

    switch (cfg->injectFlag)
    {
        case SBIT_INJECT_TABLE_LENGTH:
            beVal = SBIT_SWAP16(cfg->injectValue);
            /* tableLength is at byte offset 4 in g_sbitBuffer (after type+version) */
            memcpy(&g_sbitBuffer[4U], &beVal, sizeof(uint16_t));
            break;

        case SBIT_INJECT_SBIT_VERSION:
            beVal = SBIT_SWAP16(cfg->injectValue);
            memcpy(&g_sbitBuffer[2U], &beVal, sizeof(uint16_t));
            break;

        case SBIT_INJECT_NUM_MODULES:
        {
            /*
             * numberOfModules is the last field of the header.
             * For V1: hdrSize bytes in, minus 2.
             * For V2/V3: same relative position.
             */
            uint16_t pos = (uint16_t)(hdrSize - sizeof(uint16_t));
            beVal = SBIT_SWAP16(cfg->injectValue);
            memcpy(&g_sbitBuffer[pos], &beVal, sizeof(uint16_t));
            break;
        }

        case SBIT_INJECT_ZERO_REGIONS:
        {
            /*
             * Zero out the numRegions byte in each stage block.
             * Stage 1 block starts at: hdrSize + ModuleLocTableSize
             */
            uint16_t s1Pos = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));
            uint16_t s2Pos = (uint16_t)(s1Pos + 1U + 2U * stageCounts[0]);
            uint16_t s3Pos = (uint16_t)(s2Pos + 1U + 2U * stageCounts[1]);

            g_sbitBuffer[s1Pos] = 0U;
            g_sbitBuffer[s2Pos] = 0U;
            g_sbitBuffer[s3Pos] = 0U;
            break;
        }

        case SBIT_INJECT_INVALID_VD_S1:
        {
            /*
             * Corrupt VD index of the first region in Stage 1.
             * VD index is the 9th byte of a region entry (bytes 8, 0-based).
             * Stage 1 first region offset is stored in the stage 1 block at pos+1.
             */
            uint16_t s1Pos   = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));
            uint16_t rgnOffBE;
            uint16_t rgnOff;
            memcpy(&rgnOffBE, &g_sbitBuffer[s1Pos + 1U], sizeof(uint16_t));
            rgnOff = SBIT_SWAP16(rgnOffBE);
            g_sbitBuffer[rgnOff + 8U] = (uint8_t)cfg->injectValue;
            break;
        }

        case SBIT_INJECT_INVALID_VD_S2:
        {
            uint16_t s1Pos   = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));
            uint16_t s2Pos   = (uint16_t)(s1Pos + 1U + 2U * stageCounts[0]);
            uint16_t rgnOffBE;
            uint16_t rgnOff;
            memcpy(&rgnOffBE, &g_sbitBuffer[s2Pos + 1U], sizeof(uint16_t));
            rgnOff = SBIT_SWAP16(rgnOffBE);
            g_sbitBuffer[rgnOff + 8U] = (uint8_t)cfg->injectValue;
            break;
        }

        case SBIT_INJECT_INVALID_VD_S3:
        {
            uint16_t s1Pos   = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));
            uint16_t s2Pos   = (uint16_t)(s1Pos + 1U + 2U * stageCounts[0]);
            uint16_t s3Pos   = (uint16_t)(s2Pos + 1U + 2U * stageCounts[1]);
            uint16_t rgnOffBE;
            uint16_t rgnOff;
            memcpy(&rgnOffBE, &g_sbitBuffer[s3Pos + 1U], sizeof(uint16_t));
            rgnOff = SBIT_SWAP16(rgnOffBE);
            g_sbitBuffer[rgnOff + 8U] = (uint8_t)cfg->injectValue;
            break;
        }

        case SBIT_INJECT_CCID_ZERO:
        {
            /*
             * Find UNUSED_FLASH module and set its CCID to injectValue.
             * CCID is at the start of each Module Info block.
             */
            uint16_t base = (uint16_t)(hdrSize
                                       + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules)
                                       + SBIT_ALL_STAGES_LOC_SIZE(totalRegions));
            uint16_t m;
            for (m = 0U; m < cfg->numModules; m++)
            {
                if (cfg->modules[m].moduleId == MOD_ID_UNUSED_FLASH)
                {
                    beVal = SBIT_SWAP16(cfg->injectValue);
                    memcpy(&g_sbitBuffer[base], &beVal, sizeof(uint16_t));
                    break;
                }
                base += (uint16_t)(SBIT_MODULE_INFO_HDR_SIZE +
                         SBIT_REGION_INFO_BLOCK_SIZE(cfg->modules[m].numRegions));
            }
            break;
        }

        /* Handled inline during section writes — nothing extra needed here */
        case SBIT_INJECT_INVALID_REGION_ADDR:
        case SBIT_INJECT_LARGE_MOD_LENGTH:
        case SBIT_INJECT_R1_IN_STAGE2:
        case SBIT_INJECT_R1_IN_STAGE3:
        case SBIT_INJECT_FIXED_HBL_ADDR:
        case SBIT_INJECT_BOOT_MSG_DIGEST:
        case SBIT_INJECT_NONE:
        default:
            break;
    }
}

/*==============================================================================
 *                    PUBLIC: SBIT_Generate
 *============================================================================*/
Sbit_Status_t SBIT_Generate(const Sbit_Config_t *cfg)
{
    Sbit_Status_t  status;
    uint8_t        hdrSize;
    uint16_t       totalRegions;
    uint16_t       tableLength;
    uint8_t        stageCounts[SBIT_NUM_STAGES];
    uint16_t       stage1Offset;
    uint16_t       stage2Offset;
    uint16_t       stage3Offset;
    uint8_t        bootDigest[SBIT_SHA256_SIZE];

    /* ------------------------------------------------------------------ */
    /* 1. Validate                                                          */
    /* ------------------------------------------------------------------ */
    status = SBIT_ValidateConfig(cfg);
    if (status != SBIT_OK)
    {
        return status;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Derived values                                                    */
    /* ------------------------------------------------------------------ */
    hdrSize      = prv_HeaderSize(cfg->tableType);
    totalRegions = prv_TotalRegions(cfg);
    prv_CountStageRegions(cfg, stageCounts);

    status = SBIT_ComputeTableLength(cfg, &tableLength);
    if (status != SBIT_OK)
    {
        return status;
    }

    /*
     * Stage info offsets:
     *   Stage 1 block starts at: hdrSize + ModuleLocTableSize
     *   Stage 2 block starts at: Stage1Start + (1 + 2*S1count)
     *   Stage 3 block starts at: Stage2Start + (1 + 2*S2count)
     */
    stage1Offset = (uint16_t)(hdrSize + SBIT_MODULE_LOC_TABLE_SIZE(cfg->numModules));
    stage2Offset = (uint16_t)(stage1Offset + 1U + 2U * stageCounts[0]);
    stage3Offset = (uint16_t)(stage2Offset + 1U + 2U * stageCounts[1]);

    /* ------------------------------------------------------------------ */
    /* 3. Clear buffer                                                      */
    /* ------------------------------------------------------------------ */
    memset(g_sbitBuffer, 0, SBIT_BUFFER_SIZE);

    /* ------------------------------------------------------------------ */
    /* 4. Boot message digest                                               */
    /* ------------------------------------------------------------------ */
    memset(bootDigest, 0, SBIT_SHA256_SIZE);

    if (cfg->injectFlag != SBIT_INJECT_BOOT_MSG_DIGEST)
    {
        /* Check if caller pre-computed the digest (non-zero) */
        {
            uint8_t  isZero = 1U;
            uint8_t  i;
            for (i = 0U; i < SBIT_SHA256_SIZE; i++)
            {
                if (cfg->bootMsgDigest[i] != 0U)
                {
                    isZero = 0U;
                    break;
                }
            }

            if (!isZero)
            {
                /* Use caller-provided digest directly */
                memcpy(bootDigest, cfg->bootMsgDigest, SBIT_SHA256_SIZE);
            }
            else
            {
                /* Compute via HSM — find first HBL module */
                uint16_t hblId = MOD_ID_HBL_047;   /* default HBL to look for */
                uint16_t m;
                bool     found = false;

                for (m = 0U; m < cfg->numModules; m++)
                {
                    if ((cfg->modules[m].moduleId == MOD_ID_HBL_047) ||
                        (cfg->modules[m].moduleId == MOD_ID_HBL_048) ||
                        (cfg->modules[m].moduleId == MOD_ID_HBL_049))
                    {
                        hblId = cfg->modules[m].moduleId;
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    status = SBIT_ComputeBootDigest(cfg, hblId, bootDigest);
                    if (status != SBIT_OK)
                    {
                        return status;
                    }
                }
                /* If no HBL module present, bootDigest remains all-zero */
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* 5. Write sections into g_sbitBuffer[]                               */
    /* ------------------------------------------------------------------ */

    /* 5a. Module Location by ID table */
    prv_WriteModuleLocTable(cfg, hdrSize, totalRegions);

    /* 5b. Stage Region Location blocks */
    prv_WriteStageRegionLocBlocks(cfg, hdrSize, totalRegions);

    /* 5c. Module Info blocks (CCID + numRegions + region entries) */
    prv_WriteModuleInfoBlocks(cfg, hdrSize, totalRegions);

    /* 5d. Header (written last so all offsets are finalised) */
    prv_WriteHeader(cfg, hdrSize, tableLength,
                    stage1Offset, stage2Offset, stage3Offset,
                    bootDigest);

    /* ------------------------------------------------------------------ */
    /* 6. Apply fault injection overrides (post-write corruptions)         */
    /* ------------------------------------------------------------------ */
    prv_ApplyInjection(cfg, hdrSize, totalRegions, stageCounts);

    /* ------------------------------------------------------------------ */
    /* 7. Write to target memory                                            */
    /* ------------------------------------------------------------------ */
    SBIT_WriteToMemory((uint32_t)(uintptr_t)DEFAULT_SBIT_AUX_ADDRESS,
                       g_sbitBuffer,
                       (uint32_t)tableLength);

    return SBIT_OK;
}
