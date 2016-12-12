/*
 * Copyright (c) 2007 - 2009 NVIDIA Corporation.  All rights reserved.
 * 
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

/**
 * Defines version information for the boot rom.
 */

#ifndef INCLUDED_NVBOOT_VERSION_H
#define INCLUDED_NVBOOT_VERSION_H

#include "nvboot_version_defs.h"

/***********************************************************************/
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/*								       */
/*         Use nvboot_version_rom.h				       */
/*								       */
/***********************************************************************/

#define NVBOOT_BOOTROM_VERSION		CONST_NVBOOT_BOOTROM_VERSION
#define NVBOOT_RCM_VERSION	 	CONST_NVBOOT_RCM_VERSION
#define NVBOOT_BOOTDATA_VERSION		CONST_NVBOOT_BOOTDATA_VERSION

/**
 * Constants for the version numbers of each chip revision.
 */

/**
 * BootROM versions for each chip revision
 */
#define NVBOOT_BOOTROM_VERSION_AP15_A01_MAJOR 1
#define NVBOOT_BOOTROM_VERSION_AP15_A01_MINOR 0
#define NVBOOT_BOOTROM_VERSION_AP15_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP15_A01_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP15_A01_MINOR))

#define NVBOOT_BOOTROM_VERSION_AP15_A02_MAJOR 1
#define NVBOOT_BOOTROM_VERSION_AP15_A02_MINOR 1
#define NVBOOT_BOOTROM_VERSION_AP15_A02                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP15_A02_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP15_A02_MINOR))

#define NVBOOT_BOOTROM_VERSION_AP16_A01_MAJOR 1
#define NVBOOT_BOOTROM_VERSION_AP16_A01_MINOR 2
#define NVBOOT_BOOTROM_VERSION_AP16_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP16_A01_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP16_A01_MINOR))

#define NVBOOT_BOOTROM_VERSION_AP16_A02_MAJOR 1
#define NVBOOT_BOOTROM_VERSION_AP16_A02_MINOR 2
#define NVBOOT_BOOTROM_VERSION_AP16_A02                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP16_A02_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP16_A02_MINOR))

#define NVBOOT_BOOTROM_VERSION_AP16_A03_MAJOR 1
#define NVBOOT_BOOTROM_VERSION_AP16_A03_MINOR 3
#define NVBOOT_BOOTROM_VERSION_AP16_A03                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP16_A03_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP16_A03_MINOR))

#define NVBOOT_BOOTROM_VERSION_AP20_A01_MAJOR 2
#define NVBOOT_BOOTROM_VERSION_AP20_A01_MINOR 1
#define NVBOOT_BOOTROM_VERSION_AP20_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_AP20_A01_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_AP20_A01_MINOR))

#define NVBOOT_BOOTROM_VERSION_T30_A01_MAJOR 3
#define NVBOOT_BOOTROM_VERSION_T30_A01_MINOR 1
#define NVBOOT_BOOTROM_VERSION_T30_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTROM_VERSION_T30_A01_MAJOR,\
                  NVBOOT_BOOTROM_VERSION_T30_A01_MINOR))

/**
 * RCM versions for each chip revision
 */
#define NVBOOT_RCM_VERSION_AP15_A01_MAJOR 1
#define NVBOOT_RCM_VERSION_AP15_A01_MINOR 0
#define NVBOOT_RCM_VERSION_AP15_A01                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP15_A01_MAJOR,\
                  NVBOOT_RCM_VERSION_AP15_A01_MINOR))

#define NVBOOT_RCM_VERSION_AP15_A02_MAJOR 1
#define NVBOOT_RCM_VERSION_AP15_A02_MINOR 0
#define NVBOOT_RCM_VERSION_AP15_A02                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP15_A02_MAJOR,\
                  NVBOOT_RCM_VERSION_AP15_A02_MINOR))

#define NVBOOT_RCM_VERSION_AP16_A01_MAJOR 1
#define NVBOOT_RCM_VERSION_AP16_A01_MINOR 0
#define NVBOOT_RCM_VERSION_AP16_A01                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP16_A01_MAJOR,\
                  NVBOOT_RCM_VERSION_AP16_A01_MINOR))

#define NVBOOT_RCM_VERSION_AP16_A02_MAJOR 1
#define NVBOOT_RCM_VERSION_AP16_A02_MINOR 0
#define NVBOOT_RCM_VERSION_AP16_A02                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP16_A02_MAJOR,\
                  NVBOOT_RCM_VERSION_AP16_A02_MINOR))

#define NVBOOT_RCM_VERSION_AP16_A03_MAJOR 1
#define NVBOOT_RCM_VERSION_AP16_A03_MINOR 0
#define NVBOOT_RCM_VERSION_AP16_A03                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP16_A03_MAJOR,\
                  NVBOOT_RCM_VERSION_AP16_A03_MINOR))

#define NVBOOT_RCM_VERSION_AP20_A01_MAJOR 2
#define NVBOOT_RCM_VERSION_AP20_A01_MINOR 1
#define NVBOOT_RCM_VERSION_AP20_A01                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_AP20_A01_MAJOR,\
                  NVBOOT_RCM_VERSION_AP20_A01_MINOR))

#define NVBOOT_RCM_VERSION_T30_A01_MAJOR 3
#define NVBOOT_RCM_VERSION_T30_A01_MINOR 1
#define NVBOOT_RCM_VERSION_T30_A01                 \
  (NVBOOT_VERSION(NVBOOT_RCM_VERSION_T30_A01_MAJOR,\
                  NVBOOT_RCM_VERSION_T30_A01_MINOR))

/**
 * BootData versions for each chip revision
 */
#define NVBOOT_BOOTDATA_VERSION_AP15_A01_MAJOR 1
#define NVBOOT_BOOTDATA_VERSION_AP15_A01_MINOR 0
#define NVBOOT_BOOTDATA_VERSION_AP15_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP15_A01_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP15_A01_MINOR))

#define NVBOOT_BOOTDATA_VERSION_AP15_A02_MAJOR 1
#define NVBOOT_BOOTDATA_VERSION_AP15_A02_MINOR 0
#define NVBOOT_BOOTDATA_VERSION_AP15_A02                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP15_A02_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP15_A02_MINOR))

#define NVBOOT_BOOTDATA_VERSION_AP16_A01_MAJOR 1
#define NVBOOT_BOOTDATA_VERSION_AP16_A01_MINOR 0
#define NVBOOT_BOOTDATA_VERSION_AP16_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP16_A01_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP16_A01_MINOR))

#define NVBOOT_BOOTDATA_VERSION_AP16_A02_MAJOR 1
#define NVBOOT_BOOTDATA_VERSION_AP16_A02_MINOR 0
#define NVBOOT_BOOTDATA_VERSION_AP16_A02                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP16_A02_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP16_A02_MINOR))

#define NVBOOT_BOOTDATA_VERSION_AP16_A03_MAJOR 1
#define NVBOOT_BOOTDATA_VERSION_AP16_A03_MINOR 0
#define NVBOOT_BOOTDATA_VERSION_AP16_A03                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP16_A03_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP16_A03_MINOR))

#define NVBOOT_BOOTDATA_VERSION_AP20_A01_MAJOR 2
#define NVBOOT_BOOTDATA_VERSION_AP20_A01_MINOR 1
#define NVBOOT_BOOTDATA_VERSION_AP20_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_AP20_A01_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_AP20_A01_MINOR))

#define NVBOOT_BOOTDATA_VERSION_T30_A01_MAJOR 3
#define NVBOOT_BOOTDATA_VERSION_T30_A01_MINOR 1
#define NVBOOT_BOOTDATA_VERSION_T30_A01                 \
  (NVBOOT_VERSION(NVBOOT_BOOTDATA_VERSION_T30_A01_MAJOR,\
                  NVBOOT_BOOTDATA_VERSION_T30_A01_MINOR))

/***********************************************************************/
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/* !!!!!   THIS FILE SHOULD NOT BE INCLUDED IN BOOTROM SOURCE    !!!!! */
/***********************************************************************/


#endif /* #ifndef INCLUDED_NVBOOT_VERSION_H */
