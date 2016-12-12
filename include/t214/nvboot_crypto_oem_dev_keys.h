/*
 * Copyright (c) 2015 NVIDIA Corporation.  All rights reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

/**
 * Definition of our OEM test keys used for development and bringup.
 * Used for signing OEM assets.
 * Not for use in prouduction for obvious reasons.
 *
 * See also //hw/nvmobile_t186/drv/bootrom/BRtools/crypto_keys/oem_keys/...
 * for the same keys in big endian format for use by polarssl.
 *
 * These keys are in little endian format ready for direct inclusion into
 * the BCT and other data structures.
 *
 */

#ifndef INCLUDED_NVBOOT_CRYPTO_OEM_DEV_KEYS_H
#define INCLUDED_NVBOOT_CRYPTO_OEM_DEV_KEYS_H

// Note, only the modulus is specified here. The public exponent
// is a fixed number, 655537d or 0x10001.
static const unsigned char OemRsaPublicKeyModulus[] __attribute__ ((aligned(4))) =
{
    0xf9, 0x38, 0x07, 0x09, 0xca, 0x99, 0x47, 0xdf,
    0x5d, 0xb5, 0x38, 0x93, 0x0b, 0x3f, 0x44, 0xd4,
    0x63, 0x7e, 0xfb, 0x48, 0x53, 0xcc, 0x48, 0xf7,
    0x92, 0x0b, 0x46, 0xd4, 0x2d, 0x22, 0x17, 0xe7,
    0x56, 0x02, 0x1a, 0xb0, 0x44, 0x41, 0x49, 0x01,
    0x27, 0xcf, 0x01, 0x9d, 0x6f, 0x09, 0x13, 0x36,
    0xbc, 0x83, 0x61, 0xa3, 0x44, 0xa4, 0x1f, 0xff,
    0x02, 0x65, 0xf2, 0x1b, 0xe6, 0x9b, 0x5e, 0x65,
    0x27, 0xdd, 0x4d, 0x71, 0x05, 0x2d, 0x1d, 0x2e,
    0x39, 0x12, 0x5f, 0x7c, 0xea, 0x6c, 0xdd, 0x62,
    0x76, 0x25, 0x98, 0x13, 0xe7, 0xdd, 0x8e, 0x33,
    0x2e, 0xc1, 0x80, 0x88, 0x13, 0x00, 0xd4, 0x2e,
    0x7d, 0xbf, 0x3c, 0xdd, 0xaf, 0x51, 0x10, 0x55,
    0x61, 0xd4, 0xc6, 0xdb, 0x69, 0x3e, 0x4d, 0xec,
    0x4b, 0xd9, 0xfe, 0x36, 0x61, 0x83, 0x66, 0xc0,
    0xe1, 0x68, 0x14, 0xc0, 0x23, 0x71, 0x05, 0x79,
    0x44, 0x29, 0x5b, 0x21, 0x27, 0x4b, 0x01, 0x70,
    0x2b, 0x20, 0x67, 0x80, 0xe2, 0x22, 0x18, 0xd1,
    0x09, 0x7f, 0x45, 0x80, 0x3b, 0x6b, 0xd0, 0x3a,
    0x60, 0x26, 0x83, 0xa9, 0x0e, 0x9b, 0x4f, 0xa4,
    0x6d, 0x14, 0x22, 0x3f, 0x9c, 0x75, 0xaf, 0xa2,
    0x6c, 0x2c, 0x84, 0xd7, 0x5a, 0x04, 0x22, 0xf6,
    0xc2, 0xff, 0x95, 0xf0, 0x01, 0x19, 0x05, 0x2d,
    0xab, 0x5d, 0x6e, 0x4e, 0xcb, 0xa8, 0xa7, 0xba,
    0x18, 0x2a, 0xf3, 0x9a, 0x61, 0xdd, 0xfc, 0x56,
    0xbb, 0xe6, 0xf7, 0xa7, 0x12, 0x2c, 0xfe, 0x44,
    0xb7, 0x18, 0x42, 0x11, 0xf0, 0xf8, 0x70, 0xec,
    0xf3, 0xdd, 0x4e, 0xd7, 0xe0, 0xe2, 0x08, 0xe2,
    0x2a, 0xcb, 0x56, 0x9d, 0x72, 0x3b, 0x9a, 0x4d,
    0x42, 0x7b, 0x2c, 0x96, 0xd7, 0xdf, 0x39, 0xec,
    0x8c, 0x36, 0xca, 0x1b, 0x2a, 0xa4, 0x8d, 0xb1,
    0x73, 0xe0, 0x02, 0x8b, 0x40, 0x0e, 0xf6, 0x93,
};

static const unsigned char OemEcDevPublicKeyQx256[] __attribute__ ((aligned (4))) =
{
    0xd4, 0xe3, 0x44, 0x37, 0x74, 0x3f, 0x16, 0xbd,
    0x82, 0x52, 0x24, 0xd2, 0xe0, 0x02, 0xbc, 0xb4,
    0xd5, 0xa7, 0xb5, 0x30, 0xe8, 0xcd, 0xb7, 0xf7,
    0x92, 0x29, 0x81, 0x57, 0x6f, 0x5a, 0x22, 0x2b,
};

static const unsigned char OemEcDevPublicKeyQy256[] __attribute__ ((aligned (4))) =
{
    0xdb, 0xac, 0x97, 0xc0, 0x83, 0x5a, 0xf7, 0xde,
    0x0a, 0x4d, 0x4d, 0x91, 0xab, 0xca, 0x90, 0x66,
    0xbd, 0xbf, 0xa9, 0xef, 0x37, 0xba, 0xd6, 0xe9,
    0x8e, 0xac, 0x0e, 0xa6, 0x4d, 0x82, 0xb9, 0xe2,
};

#endif
