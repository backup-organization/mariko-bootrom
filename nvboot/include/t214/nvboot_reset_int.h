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
 * nvboot_reset_int.h - Declarations for reset support.
 *
 */

#ifndef INCLUDED_NVBOOT_RESET_INT_H
#define INCLUDED_NVBOOT_RESET_INT_H

#include "arclk_rst.h"

#if defined(__cplusplus)
extern "C"
{
#endif

// Set of reset signals supported in the API */
// The corresponding enum embeds some information on the register structure
#define NVBOOT_RESET_DEVICE_BIT_OFFSET_MASK (0x1F)
#define NVBOOT_RESET_REG_SHIFT (0x05)    
#define NVBOOT_RESET_BIT_OFFSET(DeviceId) (((NvU32) DeviceId) & NVBOOT_RESET_DEVICE_BIT_OFFSET_MASK)
#define NVBOOT_RESET_REG_OFFSET(DeviceId) (((NvU32) DeviceId) >> NVBOOT_RESET_REG_SHIFT)         

// Define enums to index into CarResetRegTbl[]    
typedef enum
{
    CarResetReg_L = 0,
    CarResetReg_H,
    CarResetReg_U,
    CarResetReg_X,
    CarResetReg_Y,
    CarResetReg_V,
    CarResetReg_W,
    CarResetReg_Num,
} NvBootCarResetRegId;

#define NVBOOT_RESET_L_REG (CarResetReg_L << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_H_REG (CarResetReg_H << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_U_REG (CarResetReg_U << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_X_REG (CarResetReg_X << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_Y_REG (CarResetReg_Y << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_V_REG (CarResetReg_V << NVBOOT_RESET_REG_SHIFT)
#define NVBOOT_RESET_W_REG (CarResetReg_W << NVBOOT_RESET_REG_SHIFT)

typedef enum
{
    NvBootResetDeviceId_CpuId    = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_CPU_RST_SHIFT,
    NvBootResetDeviceId_CopId    = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_COP_RST_SHIFT,
    NvBootResetDeviceId_I2c1Id   = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_I2C1_RST_SHIFT,
#if NVENABLE_NAND_SUPPORT

    NvBootResetDeviceId_NandId   = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_NDFLASH_RST_SHIFT,
#endif
    NvBootResetDeviceId_SdmmcId  = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_SDMMC4_RST_SHIFT,
    NvBootResetDeviceId_UartaId  = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_UARTA_RST_SHIFT,
    NvBootResetDeviceId_UsbId    = CLK_RST_CONTROLLER_RST_DEVICES_L_0_SWR_USBD_RST_SHIFT,
    NvBootResetDeviceId_McId     = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_MEM_RST_SHIFT    + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_EmcId    = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_EMC_RST_SHIFT    + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_SpiId    = CLK_RST_CONTROLLER_RST_DEVICES_Y_0_SWR_QSPI_RST_SHIFT   + NVBOOT_RESET_Y_REG,
    NvBootResetDeviceId_ApbDmaId = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_APBDMA_RST_SHIFT + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_AhbDmaId = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_AHBDMA_RST_SHIFT + NVBOOT_RESET_H_REG,


    NvBootResetDeviceId_SeId	 = CLK_RST_CONTROLLER_RST_DEVICES_V_0_SWR_SE_RST_SHIFT + NVBOOT_RESET_V_REG,
    NvBootResetDeviceId_I2c2Id   = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_I2C2_RST_SHIFT + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_I2c3Id   = CLK_RST_CONTROLLER_RST_DEVICES_U_0_SWR_I2C3_RST_SHIFT + NVBOOT_RESET_U_REG,
    NvBootResetDeviceId_I2c4Id   = CLK_RST_CONTROLLER_RST_DEVICES_V_0_SWR_I2C4_RST_SHIFT + NVBOOT_RESET_V_REG,
    NvBootResetDeviceId_I2c5Id   = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_I2C5_RST_SHIFT + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_Spi1Id	 = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_SPI1_RST_SHIFT + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_Spi2Id	 = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_SPI2_RST_SHIFT + NVBOOT_RESET_H_REG,
    NvBootResetDeviceId_Spi3Id	 = CLK_RST_CONTROLLER_RST_DEVICES_H_0_SWR_SPI3_RST_SHIFT + NVBOOT_RESET_H_REG,

#ifdef NV_MC_HAS_DUAL_CHANNEL_ENABLED
    NvBootResetDeviceId_Mc1Id        = CLK_RST_CONTROLLER_RST_DEVICES_W_0_SWR_EMC1_RST_SHIFT    + NVBOOT_RESET_W_REG,
    NvBootResetDeviceId_Emc1Id       = CLK_RST_CONTROLLER_RST_DEVICES_W_0_SWR_MC1_RST_SHIFT + NVBOOT_RESET_W_REG,
#endif
    NvBootResetDeviceId_XUsbId   = CLK_RST_CONTROLLER_RST_DEVICES_W_0_SWR_XUSB_PADCTL_RST_SHIFT    + NVBOOT_RESET_W_REG,
    NvBootResetDeviceId_XUsbSSId   = CLK_RST_CONTROLLER_RST_DEVICES_W_0_SWR_XUSB_SS_RST_SHIFT    + NVBOOT_RESET_W_REG,
    NvBootResetDeviceId_XUsbDevId   = CLK_RST_CONTROLLER_RST_DEVICES_U_0_SWR_XUSB_DEV_RST_SHIFT + NVBOOT_RESET_U_REG,
    NvBootResetDeviceId_XUsbHostId   = CLK_RST_CONTROLLER_RST_DEVICES_U_0_SWR_XUSB_HOST_RST_SHIFT + NVBOOT_RESET_U_REG,
    NvBootResetDeviceId_SataColdRstId = CLK_RST_CONTROLLER_RST_DEVICES_W_0_SWR_SATACOLD_RST_SHIFT + NVBOOT_RESET_W_REG,
    NvBootResetDeviceId_SataId = CLK_RST_CONTROLLER_RST_DEVICES_V_0_SWR_SATA_RST_SHIFT + NVBOOT_RESET_V_REG,
    NvBootResetDeviceId_SataOobId = CLK_RST_CONTROLLER_RST_DEVICES_V_0_SWR_SATA_OOB_RST_SHIFT + NVBOOT_RESET_V_REG,
 
    NvBootResetSignalId_Force32 = 0x7fffffff,
    NvBootResetDeviceId_SnorId   = NvBootResetSignalId_Force32,
    NvBootResetDeviceId_Spi5Id	 = NvBootResetSignalId_Force32,
    NvBootResetDeviceId_Spi6Id	 = NvBootResetSignalId_Force32,
    /// BSEA and VDE have been removed and are not expected to be present in future chips.
    /// They have been replaced with NVDEC.
    NvBootResetDeviceId_BseaId   = NvBootResetSignalId_Force32,
    NvBootResetDeviceId_BsevId   = NvBootResetSignalId_Force32,
    NvBootResetDeviceId_VdeId    = NvBootResetSignalId_Force32,
    /// USB3 doesn't exist in T210. USB3 here refers to third instance of legacy USB controller
    /// and not to XUSB.
    NvBootResetDeviceId_Usb3Id   = NvBootResetSignalId_Force32
} NvBootResetDeviceId;

#define NVBOOT_RESET_CHECK_ID(DeviceId) \
    NV_ASSERT( (DeviceId == NvBootResetDeviceId_CpuId)    || \
               (DeviceId == NvBootResetDeviceId_CopId)    || \
               (DeviceId == NvBootResetDeviceId_I2c1Id)   || \
               (DeviceId == NvBootResetDeviceId_SdmmcId)  || \
               (DeviceId == NvBootResetDeviceId_UartaId)  || \
               (DeviceId == NvBootResetDeviceId_UsbId)    || \
               (DeviceId == NvBootResetDeviceId_Usb3Id)   || \
               (DeviceId == NvBootResetDeviceId_McId)     || \
               (DeviceId == NvBootResetDeviceId_EmcId)    || \
               (DeviceId == NvBootResetDeviceId_BseaId)   || \
               (DeviceId == NvBootResetDeviceId_BsevId)   || \
               (DeviceId == NvBootResetDeviceId_VdeId)    || \
               (DeviceId == NvBootResetDeviceId_ApbDmaId) || \
               (DeviceId == NvBootResetDeviceId_AhbDmaId) || \
               (DeviceId == NvBootResetDeviceId_SnorId)   || \
               (DeviceId == NvBootResetDeviceId_SeId)   || \
               (DeviceId == NvBootResetDeviceId_SpiId)  || \
               (DeviceId == NvBootResetDeviceId_I2c2Id)   || \
               (DeviceId == NvBootResetDeviceId_I2c3Id)   || \
               (DeviceId == NvBootResetDeviceId_I2c4Id)   || \
               (DeviceId == NvBootResetDeviceId_I2c5Id)   || \
               (DeviceId == NvBootResetDeviceId_Spi1Id)  || \
               (DeviceId == NvBootResetDeviceId_Spi2Id)  || \
               (DeviceId == NvBootResetDeviceId_Spi3Id)  || \
               (DeviceId == NvBootResetDeviceId_Spi5Id)  || \
               (DeviceId == NvBootResetDeviceId_Spi6Id)  || \
               (DeviceId == NvBootResetDeviceId_XUsbId)    || \
               (DeviceId == NvBootResetDeviceId_XUsbSSId)    || \
               (DeviceId == NvBootResetDeviceId_XUsbHostId)    || \
               (DeviceId == NvBootResetDeviceId_XUsbDevId)    || \
               (DeviceId == NvBootResetDeviceId_SataColdRstId) || \
               (DeviceId == NvBootResetDeviceId_SataId) || \
               (DeviceId == NvBootResetDeviceId_SataOobId) || \
               0 );
#if NVENABLE_NAND_SUPPORT
               (DeviceId == NvBootResetDeviceId_NandId)   || 
#endif
#ifdef NV_MC_HAS_DUAL_CHANNEL_ENABLED
               (DeviceId == NvBootResetDeviceId_Emc1Id)    || \
               (DeviceId == NvBootResetDeviceId_Mc1Id)     || 
#endif


#define NVBOOT_RESET_STABILIZATION_DELAY (0x2)

/*
 * NvBootResetSetEnable(): Control the reset level for the identified reset signal
 */
void
NvBootResetSetEnable(const NvBootResetDeviceId DeviceId, const NvBool Enable);

/*
 * NvBootResetFullChip(): This is the highest possible reset, everything but AO is reset
 */
void
NvBootResetFullChip(void);

#if defined(__cplusplus)
}
#endif

#endif /* #ifndef INCLUDED_NVBOOT_RESET_INT_H */
