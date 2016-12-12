/*
 * Copyright (c) 2012 - 2013 NVIDIA Corporation.  All rights reserved.
 * 
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

/*
 * nvboot_wdt.c - Implementation of Watchdog
 *
 */

#include "nvcommon.h"
#include "nvrm_drf.h"
#include "arapbpm.h"
#include "arclk_rst.h"
#include "artimerus.h"
#include "artimer_wdt.h"
#include "nvboot_error.h"
#include "nvboot_hacks_int.h"
#include "nvboot_hardware_access_int.h"
#include "nvboot_irom_patch_int.h"
#include "nvboot_pmc_int.h"
#include "nvboot_wdt_int.h"
#include "nvboot_fuse_int.h"
#include "nvboot_util_int.h"
#include "project.h"
      
//Bug 867069 : Refer to bug for design details
//For wdt and timer related register details 
//Refer to arwdt_single.spec and artimer_single.spec under //hw/t*/defs
NvBool
NvBootWdtGetStatus(void)
{
    NvU32 RegData;

    RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_STATUS_0);
    RegData = NV_DRF_VAL(TIMER, WDT4_STATUS, Enabled, RegData);
    if(RegData)
    {
        //wdt timer is running
        return NV_TRUE;
    }
    return NV_FALSE;
}

void
NvBootWdtInit(void)
{
    NvU32 RegData;
    
    // program Watchdog config register
    // Pmc2CarResetEn     - will reset all of AO logic + SOC logic 
    // SystemResetEnable  - will reset the SOC logic only (will not reset AO logic)
    // Period field sets wdt period and is = Period * timer value loaded in timer selected by TimerSource
    // Watchdog hw resets the system after 4th expiration of the watchdog period
    // CurrentExpirationCount in wdt status gets incremented after each expiration of wdt
    RegData = NV_DRF_DEF(TIMER, WDT4_CONFIG, TimerSource, TMR1)| \
              NV_DRF_NUM(TIMER, WDT4_CONFIG, Period, 1) | \
              NV_DRF_DEF(TIMER, WDT4_CONFIG,InterruptEnable, DISABLE) | \
              NV_DRF_DEF(TIMER, WDT4_CONFIG,FIQEnable, DISABLE) | \
              NV_DRF_DEF(TIMER, WDT4_CONFIG,Pmc2CarResetEn, ENABLE) |\
              NV_DRF_NUM(TIMER, WDT4_CONFIG,CoreResetBitmapEn, 0);
    NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_CONFIG_0, RegData);

    //clear any pending interrupts generated by timer
    RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PCR_0);
    RegData = NV_FLD_SET_DRF_NUM(TIMER, TMR1_TMR_PCR, INTR_CLR, 1, RegData);
    NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PCR_0, RegData);
    
    //Load default timer value
    //It is assumed that TIMERUS_USEC_CFG is properly set for current oscillator frequency 
    //For details refer to NvBootMainNonsecureRomEnter() -> NvBootMainNonsecureConfigureClocks()-> NvBootClocksConfigureUsecTimer()
    //PER is set so that timer gets reloaded after it reaches the timeout value
    RegData = NV_DRF_NUM(TIMER, TMR1_TMR_PTV, TMR_PTV, (WDT_TIMEOUT_VAL_NONRCM - 1))| \
              NV_DRF_DEF(TIMER, TMR1_TMR_PTV, PER, ENABLE );
    NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0, RegData);
}

void
NvBootWdtStart(void)
{
    NvU32 RegData;
    //Enable Timer
    RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0);
    RegData = NV_FLD_SET_DRF_DEF(TIMER, TMR1_TMR_PTV, EN, ENABLE, RegData );
    NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0, RegData);
    //Start Watchdog counter
    RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_COMMAND_0);
    RegData = NV_FLD_SET_DRF_NUM(TIMER, WDT4_COMMAND, StartCounter, 1,RegData);
    NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_COMMAND_0, RegData);
}

void
NvBootWdtStop(void)
{
    NvU32 RegData;
    
    //check if watchdog is running
    if (NvBootWdtGetStatus())
    {
        //Disable timer
        RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0);
        RegData = NV_FLD_SET_DRF_DEF(TIMER, TMR1_TMR_PTV, EN, DISABLE, RegData );
        NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0, RegData);

        //Writing unlock pattern is required to write to DisableCounter field. 
        //Pattern is reset at each write to command register.
        NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_UNLOCK_PATTERN_0, 0xc45a);
        //Now Disable Watchdog counter
        RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_COMMAND_0);
        RegData = NV_FLD_SET_DRF_NUM(TIMER, WDT4_COMMAND, DisableCounter, 1,RegData);
        NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_WDT4_COMMAND_0, RegData);

        //clear any pending interrupts generated by timer
        RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PCR_0);
        RegData = NV_FLD_SET_DRF_NUM(TIMER, TMR1_TMR_PCR, INTR_CLR, 1, RegData);
        NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PCR_0, RegData);
    }

}

void
NvBootWdtReload(NvU32 WatchdogTimeout)
{
    NvU32 RegData;
    
    //check if watchdog is running
    if (NvBootWdtGetStatus())
    {
        //Stop the watchdog timer first
        NvBootWdtStop();

        //Load timeout value in timer
        RegData = NV_READ32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0);
        RegData = NV_FLD_SET_DRF_NUM(TIMER, TMR1_TMR_PTV, TMR_PTV, (WatchdogTimeout - 1), RegData);
        NV_WRITE32(NV_ADDRESS_MAP_TMR_BASE + TIMER_TMR1_TMR_PTV_0, RegData);
        //Start Watchdog
        NvBootWdtStart();
    }
}

