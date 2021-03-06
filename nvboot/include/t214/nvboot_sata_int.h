/*
 * Copyright (c) 2009 NVIDIA Corporation.  All rights reserved.
 * 
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

/*
 * nvboot_sata_int.h - Public definitions for using SATA as the second level
 * boot device. These definitions are not needed outside bootrom.
 */

#ifndef INCLUDED_NVBOOT_SATA_INT_H
#define INCLUDED_NVBOOT_SATA_INT_H

#include "nvboot_device_int.h"
#include "nvboot_error.h"
#include "nvboot_sata_context.h"
#include "nvboot_sata_param.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/**
 * Returns a pointer to a device-specific structure of device parameters
 * in the ROM.  Later, the init routine will use them to configure the device.
 *
 * @param ParamIndex Parma Index that comes from Fuse values.
 * @param Params double pointer to retunr Param info based on 
 *          the param index value.
 * 
 */
void
NvBootSataGetParams(
    const NvU32 ParamIndex,
    NvBootSataParams **Params);

/**
 * Checks the contents of the parameter structure and returns NV_TRUE
 * if the parameters are all legal, NV_FALSE otherwise.
 *
 * @param Params Pointer to Param info that needs validation.
 *
 * @retval NV_TRUE The parameters are valid.
 * @retval NV_FALSE The parameters would cause an error if used.
 */
NvBool
NvBootSataValidateParams(
    const NvBootSataParams *Params);

/**
 * Queries the block and page sizes for the device in units of log2(bytes).
 * Thus, a 1KB block size is reported as 10.
 * 
 * @param Params Pointer to Param info.
 * @param BlockSizeLog2 returns block size in log2 scale.
 * @param PageSizeLog2 returns page size in log2 scale.
 * 
 */
void
NvBootSataGetBlockSizes(
    const NvBootSataParams *Params,
    NvU32 *BlockSizeLog2,
    NvU32 *PageSizeLog2);

/**
 * Uses the data pointed to by DeviceParams to initialize
 * the device for reading.  Note that the routine will likely be called
 * multiple times - once for initially gaining access to the device,
 * and once to use better parameters stored in the device itself.
 *
 * DriverContext is provided as space for storing device-specific global state.
 * Drivers should keep this pointer around for reference during later calls.
 *
 * @param ParamData Pointer to Param info to initialize the Nand with.
 * @param Context Pointer to memory, where nand state is saved to.
 *
 * @retval NvBootError_Success No Error
 */
NvBootError
NvBootSataInit(
    const NvBootSataParams *ParamData,
    NvBootSataContext *Context);

/**
 * Initiate the reading of a page of data into Dest.buffer.
 * 
 * @param Block Block number to read from.
 * @param Page Page number in the block to read from. 
 *          valid range is 0 <= Page < PagesPerBlock.
 * @param Dest Buffer to read the data into.
 *
 * @retval NvBootError_Success No Error
 */
NvBootError
NvBootSataReadPage(
    const NvU32 Block,
    const NvU32 Page,
    NvU8 *Dest);

/**
 * Check the status of read operation that is launched with 
 *  API NvBootNandReadPage, if it is pending.
 *
 * @retval NvBootDeviceStatus_Idle - Read operation is complete.
 */
NvBootDeviceStatus NvBootSataQueryStatus(void);

/**
 * Shutdowns device and cleans up the state.
 * 
 */
void NvBootSataShutdown(void);

/*
 * Allocates buffers to be used by reader code.
 * @param ReaderBuffersBase points to a valid memory physical address at which
 *        the total number of bytes required for reader code to use, have been
 *        allocated.
 * @param  requested aligment of memory.
 * @param number of bytes
 *
 * @retval NvBootError_NotInitialized Memory not initialized. (Currently, specific to 
 *         dram initialization).
 * @retval NvBootError_MemoryNotAllocated if function is implemented, but memory was
 *         was not successfully allocated or the memory address is invalid.
 * @retval NvBootError_MemoryNotAligned if the function is implemented, memory is allocated
 *         but is not aligned as requested. The alignment requirements are use with 
 *         secondary boot device controller as well as with engines.
 * @retval NvBootError_IllegalParameter if function is implemented, but ReaderBuffersBase
 *         is non-NULL which can possibly lead to memory corruption at a later point
 *         and may go un-noticed.
 * @retval NvBootError_Success if function is implemented, memory was successfully
 *         allocated and the address is returned.
 */
NvBootError NvBootSataGetReaderBuffersBase(NvU8** ReaderBuffersBase,
                                           const NvU32 Alignment, const NvU32 Bytes);

#if defined(__cplusplus)
}
#endif

#endif /* #ifndef INCLUDED_NVBOOT_SATA_INT_H */
