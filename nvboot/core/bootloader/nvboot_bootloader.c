/*
 * Copyright (c) 2014 NVIDIA Corporation.  All rights reserved.
 * 
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

/*
 * nvboot_bootloader.c - Implementation of Boot Loader support.
 */

#include "nvboot_bootloader_int.h"
#include "nvboot_bit.h"
#include "nvboot_config.h"
#include "nvboot_context_int.h"
#include "nvboot_error.h"
#include "nvboot_fuse_int.h"
#include "nvboot_reader_int.h"
#include "nvboot_sdram_int.h"
#include "nvboot_se_int.h"
#include "nvboot_util_int.h"
#include "nvboot_crypto_mgr_int.h"
#include "nvboot_rcm.h"
#include "nvboot_se_defs.h"
#include "nvboot_sdram_wrapper_int.h"
#include "nvboot_address_int.h"
#include "nvboot_oem_boot_binary_header.h"
#include "nvboot_bootloader_int.h"

/* Global data */
extern NvBootInfoTable   BootInfoTable;
extern NvBootConfigTable *pBootConfigTable;
extern NvBootCryptoMgrPublicBuf *pPublicCryptoBufR5;
extern void NvBootMainNonSecureBootLoader();

 // This buffer should be the size of the largest page size supported by bootrom. Adjust accordingly
#define FirstBufPageSize (NV_ICEIL(sizeof(NvBootOemBootBinaryHeader), NVBOOT_MAX_SECONDARY_BOOT_DEVICE_PAGE_SIZE) * NVBOOT_MAX_SECONDARY_BOOT_DEVICE_PAGE_SIZE)
static NvU8 FirstPageBuffer[FirstBufPageSize];

/* Function prototypes */
static NvBootError
LoadOneBootLoader(
    NvBootContext    *Context,
    NvBootLoaderInfo *Info);

/*
 * LoadOneBootLoader(): Read a single bootloader.
 *
 * @param Context The current context
 * @param Info    Boot loader information from the BCT
 * @param NumCopies The number of copies of the bootloader, each with its
 * own information structure.
 * 
 * @retval NvBootError_InvalidParameter NumCopies was too large
 * @retval TODO Errors from NvBootReadOneObject()
 *
 * Upon successful completion, the requested bootloader will be loaded into
 * its destination and validated.
 */
static NvBootError
LoadOneBootLoader(
    NvBootContext    *Context,
    NvBootLoaderInfo *BlInfo)
{
    NvBootError             e;
    NvBootDevMgr *DevMgr;
    NvBootDeviceStatus      ReadStatus;
    NvBootOemBootBinaryHeader *OemBootBinaryHeader;
    uint32_t HeaderSize = sizeof(NvBootOemBootBinaryHeader);

    DevMgr = &(Context->DevMgr);
    
    uint32_t PageSize= 1<<DevMgr->PageSizeLog2;
    uint32_t PagesPerBlock = 1<< (DevMgr->BlockSizeLog2-DevMgr->PageSizeLog2);
    
    /// Read and Parse Oem header. Read a complete page. Bootloader is expected to follow OemBootBinaryHeader
    NV_BOOT_CHECK_ERROR(DevMgr->Callbacks->Read(BlInfo->StartBlock,
                                   BlInfo->StartPage,
                                   HeaderSize,
                                   &FirstPageBuffer[0]));

    /// Poll till Status changes from ReadInProgress.
    while((ReadStatus = DevMgr->Callbacks->QueryStatus()) == \
           NvBootDeviceStatus_ReadInProgress);

    if(ReadStatus != NvBootDeviceStatus_Idle)
        return NvBootError_DeviceReadError;

    // Cast Header pointer to buffer just read.
    OemBootBinaryHeader = (NvBootOemBootBinaryHeader*)&FirstPageBuffer[0];
    
    /// Legacy check to confirm if bootloader + header fits inside partition. Not sure if this is needed.
    if((BlInfo->StartBlock*PagesPerBlock + BlInfo->StartPage)*PageSize + HeaderSize + OemBootBinaryHeader->Length > pBootConfigTable->PartitionSize)
    {
        return NvBootError_IllegalParameter;
    }
    
    /// Authenticate OemBootBinaryHeader hashes. This gives the length of Bl/Nv+Mv1 Package.
    NV_BOOT_CHECK_ERROR(NvBootCryptoMgrAuthOemBootBinaryHeader(OemBootBinaryHeader));

    uint32_t OemMb1LoadAddress = OemBootBinaryHeader->LoadAddress;

    /// Validate load address and length.
    /// Load address can be in IRAM B to D range or in the SDRAM range, capped at
    /// 2GB size (i.e. only one of e_IramBlCheck or e_SdramBlCheck needs to pass).
    NvBootError e_IramBlCheck = NvBootValidateAddress(BlRamRange, OemMb1LoadAddress, OemBootBinaryHeader->Length);
    NvBootError e_SdramBlCheck = NvBootValidateAddress(DramRange, OemMb1LoadAddress, OemBootBinaryHeader->Length);

    if ((e_IramBlCheck != NvBootError_Success) && (e_SdramBlCheck != NvBootError_Success))
        return NvBootError_Invalid_Bl_Load_Address;

    /// Validate EntryPoint
    NV_BOOT_CHECK_ERROR(NvBootValidateEntryPoint(OemMb1LoadAddress, OemBootBinaryHeader->Length,OemBootBinaryHeader->EntryPoint));
    
    /// Part of Bootloader has already been read into FirstPageBuffer. Copy into LoadAddress
    /// It is guaranteed that FirstPageBuffer can hold atleast OemMb1Header
    uint32_t BlFirstPageBytes = ALIGN_ADDR(HeaderSize, PageSize)-HeaderSize;
    NvBootUtilMemcpy((uint8_t*)OemMb1LoadAddress, &FirstPageBuffer[HeaderSize], BlFirstPageBytes);
    
    /// if Bootloader length is less than extra bytes read as part of Header, then we don't have anymore 
    /// reading to do. Otherwise read the remaining bytes.
    uint32_t BlLengthRemaining = (OemBootBinaryHeader->Length < BlFirstPageBytes) ? 0: (OemBootBinaryHeader->Length - BlFirstPageBytes);
    
    if(BlLengthRemaining)
    {
        uint32_t NextPage, NextBlock;
        NextPage = BlInfo->StartPage + NV_ICEIL(HeaderSize, PageSize);
        NextBlock = BlInfo->StartBlock;
        if(NextPage>=PagesPerBlock)
        {
            NextPage-=PagesPerBlock;
            NextBlock++;
        }

        /// Validate if remaining Bootloader length triggers a read that goes past allocated buffer.
        NvBootError e_IramBlCheck = NvBootValidateAddress(BlRamRange, (OemMb1LoadAddress+BlFirstPageBytes), ALIGN_ADDR(BlLengthRemaining, PageSize));
        NvBootError e_SdramBlCheck = NvBootValidateAddress(DramRange, (OemMb1LoadAddress+BlFirstPageBytes), ALIGN_ADDR(BlLengthRemaining, PageSize));

        if ((e_IramBlCheck != NvBootError_Success) && (e_SdramBlCheck != NvBootError_Success))
            return NvBootError_Invalid_Bl_Load_Address;
        
        /// Initiate the bootloader read.
        NV_BOOT_CHECK_ERROR(DevMgr->Callbacks->Read(NextBlock,
                                       NextPage,
                                       BlLengthRemaining,
                                       (uint8_t*)(OemMb1LoadAddress+BlFirstPageBytes)));

        /// Poll till Status changes from ReadInProgress.
        while((ReadStatus = DevMgr->Callbacks->QueryStatus()) == \
               NvBootDeviceStatus_ReadInProgress);

        if(ReadStatus != NvBootDeviceStatus_Idle)
            return NvBootError_DeviceReadError;
    }
    
    /// Authenticate Oem Mb1 Package
    NV_BOOT_CHECK_ERROR(NvBootCryptoMgrAuthBlPackage(OemBootBinaryHeader, (uint32_t*)OemMb1LoadAddress));

    /// Decrypt Oem Mb1 Package
    NV_BOOT_CHECK_ERROR(NvBootCryptoMgrDecryptBlPackage(OemBootBinaryHeader, (uint32_t*)OemMb1LoadAddress));

    /// Check BCT <--> OEM Boot Binary Header version binding.
    NV_BOOT_CHECK_ERROR(NvBootBootLoaderCheckVersionBinding(BlInfo, OemBootBinaryHeader));
    
    // Save validated entry point (validated above in NvBootValidateEntryPoint().
    Context->BootLoader = (uint8_t*)OemBootBinaryHeader->EntryPoint;

    return e;
}

NvBootError
NvBootBootLoaderCheckVersionBinding(NvBootLoaderInfo *BootLoaderInfo, NvBootOemBootBinaryHeader *OemBootBinaryHeader)
{
    if(BootLoaderInfo->Version == 0)
    {
        // BCT <--> BL binary disabled.
        return NvBootError_Success;
    }

    if(BootLoaderInfo->Version == OemBootBinaryHeader->Version)
    {
        return NvBootError_Success;
    }
    else
    {
        // BCT <--> BL binary version binding mismatch.
        return NvBootError_BCTVersionAndOemHeaderVersionMismatch;
    }
}

/**
 * NvBootLoadBootLoader(): Attempt to load a boot loader.
 *
 * @param[in] Context The current context
 * bootloader.  This should be an appropriate entry point.
 *
 * @retval NvBootError_Success A bootloader was successfully loaded.
 * @retval TODO Error codes from LoadOneBootLoader
 * @retval NvBootError_BootLoaderLoadFailure No boot loader could be loaded
 * successfully.
 * @retval NvBootError_InvalidBlDst The bootloader didn't fit in a valid
 * memory space or the entry point was outside the BL.
 *
 * The search algorithm for valid bootloaders:
 *      * Start with the bootloader described in entry 0 of the BCT BL table.
 *      * Try to load this bootloader.  Redundant copies are identified as
 *        bootloaders in adjacent BCT BL table entries with the same version
 *        number.
 *      * Repeat for other bootloaders described in the BCT in consecutive
 *        positions in the BCT BL table.  Higher valued indices denote older
 *        bootloaders.
 * It is assumed that the code that generated the BCT BL table understands
 * this algorithm and provided reasonable data.  Incorrect data can lead
 * to the wrong bootloader being loaded.
 */
NvBootError
NvBootLoadBootLoader(NvBootContext *Context)
{
    NvU32       BootLoaderIndex;
    NvU32       MaxBootLoader;
    NvBootError Error = NvBootError_Success;
    NvBootLoaderInfo *BlInfo = NULL;

    /*
     * Loop over available boot loaders and try to load each one
     * until successful.
     */
    /// Bootloader to use in case of failure. This will be overridden once 
    /// we successfully read the bootloader
    Context->BootLoader = (uint8_t*)NvBootMainNonSecureBootLoader;
    BootLoaderIndex = 0;
    MaxBootLoader = pBootConfigTable->BootLoadersUsed;

    while (BootLoaderIndex < MaxBootLoader)
    {
        /* Attempt to load the next boot loader. */
        BlInfo = &(pBootConfigTable->BootLoader[BootLoaderIndex]);

        Error = LoadOneBootLoader(Context, BlInfo);
        switch (Error)
        {
            case NvBootError_Success:
                BootInfoTable.BlState[BootLoaderIndex].Status =
                    NvBootRdrStatus_Success;

                return NvBootError_Success;

            case NvBootError_HashMismatch:
            case NvBootError_ValidationFailure:
                TODO
                // TODO: make sure all possible error codes from RSA-PSS verify handled here
            case NvBootError_SE_RsaPssVerify_Inconsistent:
                BootInfoTable.BlState[BootLoaderIndex].Status =
                    NvBootRdrStatus_ValidationFailure;
                break;

            case NvBootError_DeviceReadError:
            case NvBootError_HwTimeOut:
                BootInfoTable.BlState[BootLoaderIndex].Status =
                    NvBootRdrStatus_DeviceReadError;
                break;

            default:
                NV_ASSERT(0);
        }

    BootLoaderIndex++;
    }
    
    /* This point is reached if no boot loader could be successfully loaded. */
    Error = NvBootError_BootLoaderLoadFailure;

    return Error;
}

