/*
 * Copyright (c) 2007 - 2012 NVIDIA Corporation.  All rights reserved.
 *
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

#include "nvtypes.h"
#include "nvrm_drf.h"
#include "nvboot_bit.h"
#include "nvboot_buffers_int.h"
#include "nvboot_config.h"
#include "nvboot_config_int.h"
#include "nvboot_wdt_int.h"
#include "nvboot_error.h"
#include "nvboot_fuse.h"
#include "nvboot_nv_header.h"
#include "nvboot_fuse_int.h"
#include "nvboot_hacks_int.h"
#include "nvboot_irom_patch_int.h"
#include "nvboot_rcm_int.h"
#include "nvboot_se_aes.h"
#include "nvboot_se_int.h"
#include "nvboot_se_hash.h"
#include "nvboot_se_rsa.h"
#include "nvboot_util_int.h"
#include "nvboot_version_rom.h"
#include "nvboot_rcm_port_int.h"
#include "nvboot_crypto_param.h"
#include "nvboot_crypto_mgr_int.h"
#include "nvboot_strap_int.h"
#include "nvboot_context_int.h"
#include "nvboot_bpmp_int.h"
#include "nvboot_version_rom.h"
#include "nvboot_car_int.h"
#include "nvboot_address_int.h"
#include "nvboot_debug_int.h"
#include "nvboot_usbcharging_int.h"
#include "arapbpm.h"

/* Local state structure */
typedef struct NvBootRcmStateRec
{
    NvBootFuseOperatingMode RcmOpMode;
    NvBootObjectSignature   ComputedSignature;
    NvBool                  IsPublicKeyValidated;
    NvBool                  FactorySecureProvisioningMode;
    uint8_t                    ProvisioningKeyNum;
    NvBool                  FirstMessageProcessed;
} NvBootRcmState;


#define RCM_TX_BUFFER_SIZE (4096)
uint8_t RcmTxBuffer[RCM_TX_BUFFER_SIZE] __attribute__((aligned(4)));
#define RCM_TX_BUFFER (&RcmTxBuffer[0])
// CRYPTO BUFFER for holding SHA HASH.
// 512 bytes for now. This is hold any hash calculted.
#define RCM_CRYPTO_SIZE             (0x200)
uint8_t RcmCryptoBuffer[RCM_CRYPTO_SIZE] __attribute__((aligned(4)));
#define RCM_CRYPTO_BUFFER_START     (&RcmCryptoBuffer[0])



/* External data */
extern NvBootInfoTable BootInfoTable;
extern NvBootContext     Context;

/*
 * Compile-time assertion that the hashable & decryptable portion of
 * NvBootRcmMsg is a multiple of 16 bytes.
 */
NV_CT_ASSERT(((sizeof(NvBootRcmMsg) - offsetof(NvBootRcmMsg, RandomAesBlock)) & 0xf) == 0);
//NV_CT_ASSERT((sizeof(NvBootRcmMsg) & 0xf) == 0);

extern uint32_t __stack_top;

NV_CT_ASSERT(NVBOOT_RCM_MSG_IRAM_START>=__stack_top);
/*
 * Function Prototypes
 */


static NvBootRcmState s_State;

// static NvBootRcmSeInputLinkedList   s_SeInputLL;


static NvBootError SendUniqueId(void);
static NvBootError SendResponse(NvU32 Response);
static void        HandleError(NvU32 Response);

static NvBootError ProcessMsgForSecureProvisioning(NvBootRcmMsg *pRcmMsg);
NvBootError ReceiveMessage(NvBootRcmMsg*);
NvBootError Validate(NvBootRcmMsg*);
NvBootError Execute(NvBootRcmMsg*, NvBool *AppletDownloaded);

/* Synchronous transmission */
static NvBootError SendUniqueId(void)
{
    uint8_t               *SendBuffer;
    NvBootError BootError = NvBootError_Success;
    NvU32 BytesTransmitted;
    NvBootRCMPort_T   *pRcmPort = NvBootRcmGetPortHandle();

    SendBuffer = (uint8_t*)RCM_TX_BUFFER;
    NvBootUtilMemset(SendBuffer, 0, sizeof(NvBootECID));

    /* Read the ECID into the send buffer. */
    NvBootFuseGetUniqueId((NvBootECID *)SendBuffer);

    /* Encode additional information into ECID, as defined in
     * the ISS */
    NvBootFuseAddAdditionalEcidInfo((NvBootECID *)SendBuffer);

    pRcmPort->TransferStart(SendBuffer, sizeof(NvBootECID));

    /*
     * Query the endpoint status until the transfer is completed, there
     * is an error detected over the USB, or cable disconnect.
     */
    BootError = pRcmPort->TransferPoll(&BytesTransmitted, 0xFFFFFFFF, NULL);
    return BootError;
}

/* Synchronous transmission */
static NvBootError
SendResponse(NvU32 Response)
{
    NvBootError  e;
    uint8_t        *SendBuffer;
    NvU32        BytesTransmitted;
    NvBootRCMPort_T   *pRcmPort = NvBootRcmGetPortHandle();
    /*
     * Use the second buffer of the buffer pair, in case a receive is
     * in progress on the other buffer.
     */

    SendBuffer = (uint8_t*)RCM_TX_BUFFER;

    *((NvU32*)SendBuffer) = Response;

    e = pRcmPort->Transfer(SendBuffer, sizeof(NvU32), &BytesTransmitted);

    return e;
}


static void HandleError(NvU32 Response)
{
    NvBootRCMPort_T   *pRcmPort = NvBootRcmGetPortHandle();
    // The caller will report an error, so it doesn't matter if
    // the sending of the response fails.
    (void)SendResponse(Response);

    // Stall the endpoint
    pRcmPort->HandleError();
}

static NvBool IsValidInsecureLength(NvBootRcmMsg *pRcmMsg)
{
    NvU32 Length;
    const NvU32 UnsignedLengthModAESBlk = ((NvU32)&(pRcmMsg->RandomAesBlock) - (NvU32)pRcmMsg) % NVBOOT_SE_AES_BLOCK_LENGTH_BYTES;

    Length = pRcmMsg->LengthInsecure;
    if (Length >= NVBOOT_RCM_MAX_MSG_LENGTH) return NV_FALSE;
    if (Length <  NVBOOT_RCM_MIN_MSG_LENGTH) return NV_FALSE;

    /* For AES reasons, the hashed (& encrypted in OdmSecure) portions of
     * the message must be a multiple of 16 bytes.  The unsigned
     * length AES block remainder should be everything before RandomAesBlock % 16.
     */
    if ((Length % NVBOOT_SE_AES_BLOCK_LENGTH_BYTES) != UnsignedLengthModAESBlk) return NV_FALSE;

    return NV_TRUE;
}

/**
 * Begin by storing the received data into the header structure.
 * Once the header is complete, the remaining data fills the 96KB starting at
 * 0x40008000.
 *
 * Notes:
 *   BytesLeftInMessage refers to data remaining to be copied.
 *   BytesRead counts the amount of data that has been read from USB.
 *   ReadFromPort is true on all cycles of the while() loop where there is
 *     reading from USB.
 */
NvBootError ReceiveMessage(NvBootRcmMsg *pRcmMsgHeader)
{
    
    NvBootError  e;
    uint8_t        *pRcmDest;
    NvU32 TotalBytesRead, BytesRead, RcmMsgAndPayloadComplete, RcmMsgAndPayloadLen;
    NvU32 RcmHeaderRead, ReceiveLength;
    
    NvBootRCMPort_T *pRcmPort = NvBootRcmGetPortHandle();
    
    // Set all flags to 0.
    TotalBytesRead = BytesRead = 0;
    RcmMsgAndPayloadComplete = 0;
#define LENGTH_64K (64*1024)
    ReceiveLength = 0;
    RcmMsgAndPayloadLen = LENGTH_64K+1;
    RcmHeaderRead = 0;


    pRcmDest = (uint8_t*)pRcmMsgHeader;
    while(!RcmMsgAndPayloadComplete)
    {
        // Prime for 64K. This is supported by XUSB DEVICE.
        // If we have to support future devices over RCM, change receive length accordingly.
        // But prime for extra. Driver should be able to receive lesser bytes than primed for.
        
        ReceiveLength = NV_MIN(RcmMsgAndPayloadLen-TotalBytesRead, LENGTH_64K);
        
        e = pRcmPort->Receive(pRcmDest+TotalBytesRead, ReceiveLength, &BytesRead);
        if(e != NvBootError_Success)
            return e;

        TotalBytesRead += BytesRead;

        // If we did n't read the header.
        if(!RcmHeaderRead)
        {
            // If we read enough bytes of the header.
            if(TotalBytesRead >= sizeof(NvBootRcmMsg))
            {
                RcmMsgAndPayloadLen = pRcmMsgHeader->LengthInsecure;
                RcmHeaderRead = 1;
                if (!IsValidInsecureLength(pRcmMsgHeader))
                {
                    HandleError(NvBootRcmResponse_InvalidInsecureLength);
                    return NvBootError_ValidationFailure;
                }
            }
        }
        // Check if we read the whole RCM Msg.        
        if(RcmHeaderRead && (TotalBytesRead >= RcmMsgAndPayloadLen))
            RcmMsgAndPayloadComplete = 1;
        
    }

    /* Message was successfully received. */
    return  NvBootError_Success;
}

NvBootError
Validate(NvBootRcmMsg *pRcmMsg)
{
    NvU32  PaddingSize;
    uint8_t  *PaddingStart;
    NvBootError e = NvBootError_Success;

    // Set PCP. If CryptoMgr determines we are in RSA or ECC mode, 
    // it will set Public key after verifying against hash in fuses.
    // For other modes, it will return true always.

    e = NvBootCryptoMgrSetOemPcp(&pRcmMsg->Pcp);
    if(e != NvBootError_Success && 
       e != NvBootError_CryptoMgr_Pcp_Not_Loaded_Not_PK_Mode)
    {
        HandleError(NvBootRcmResponse_PublicKeyNotValidated);
        return NvBootError_ValidationFailure;
    }

    // Check if this is secure provisioning mode first
    if(s_State.FirstMessageProcessed == NV_FALSE)
    {
        e = ProcessMsgForSecureProvisioning(pRcmMsg);

        // If an invalid key was sent as part of the RCM message, return
        // an error code and exit RCM.
        if(e == NvBootError_SecProvisioningInvalidKeyInput)
        {
            HandleError(NvBootRcmResponse_SecProvisioningRcmInvalidKeyInput);
            return e;
        }
    }

    if(Context.FactorySecureProvisioningMode == NV_TRUE)
    {
        e = NvBootCryptoMgrAuthRcmPayloadFskp(pRcmMsg);
        if(e != NvBootError_Success)
        {
            HandleError(NvBootRcmResponse_HashOrSignatureCheckFailed);
            return e;
        }

        e = NvBootCryptoMgrDecryptRcmPayloadFskp(pRcmMsg);
        if(e != NvBootError_Success)
        {
            if(e == NvBootError_SecProvisioningBctKeyMismatch)
            {
                HandleError(NvBootRcmResponse_SecProvisioningRcmKeyMismatch);
            }
            else
            {
                HandleError(NvBootRcmResponse_DecryptionError);
            }
            return e;
        }
    }
    else
    {
        // AES-CMAC/RSA-PSS authenticate the msg.
        e = NvBootCryptoMgrOemAuthRcmPayload(pRcmMsg);

        if(e != NvBootError_Success)
        {
            HandleError(NvBootRcmResponse_HashOrSignatureCheckFailed);
            return e;
        }

        // Decrypt message in encrypted. Cryptomgr will sense this from fuses and
        // do the needful.
        e = NvBootCryptoMgrOemDecryptRcmPayload(pRcmMsg);
                                
        if(e != NvBootError_Success)
        {
            HandleError(NvBootRcmResponse_DecryptionError);
            return e;
        }
    }
    if (pRcmMsg->LengthInsecure != pRcmMsg->LengthSecure)
    {
        HandleError(NvBootRcmResponse_LengthMismatch);
        return NvBootError_ValidationFailure;
    }

    if (pRcmMsg->PayloadLength > (pRcmMsg->LengthSecure - sizeof(NvBootRcmMsg)))
    {
        HandleError(NvBootRcmResponse_PayloadTooLarge);
        return NvBootError_ValidationFailure;
    }
    
    /* Check Msg padding */
    if (!NvBootUtilIsValidPadding(pRcmMsg->Padding, NVBOOT_RCM_MSG_PADDING_LENGTH))
    {
        HandleError(NvBootRcmResponse_BadMsgPadding);
        return NvBootError_ValidationFailure;
    }

    /* Check Data padding */
    PaddingStart = ADDR_TO_PTR(NVBOOT_BL_IRAM_START +
                               pRcmMsg->PayloadLength);
    PaddingSize = pRcmMsg->LengthSecure - pRcmMsg->PayloadLength -
      sizeof(NvBootRcmMsg);

    if (!NvBootUtilIsValidPadding(PaddingStart, PaddingSize))
    {
        HandleError(NvBootRcmResponse_BadDataPadding);
        return NvBootError_ValidationFailure;
    }

    /* Command-specific checks */
    switch (pRcmMsg->Opcode)
    {
        case NvBootRcmOpcode_Sync:
        case NvBootRcmOpcode_QueryBootRomVersion:
        case NvBootRcmOpcode_QueryRcmVersion:
        case NvBootRcmOpcode_QueryBootDataVersion:
        case NvBootRcmOpcode_SetDebugFeatures:
            if (pRcmMsg->PayloadLength > 0)
            {
                HandleError(NvBootRcmResponse_PayloadTooLarge);
                return NvBootError_ValidationFailure;
            }
            break;

        case NvBootRcmOpcode_ProgramFuses:
        case NvBootRcmOpcode_VerifyFuses:
        case NvBootRcmOpcode_ProgramFuseArray:
        case NvBootRcmOpcode_VerifyFuseArray:
        case NvBootRcmOpcode_EnableJtag:
            // ProgramFuses ,  VerifyFuses, ProgramFuseArray & VerifyFuseArray
            // are not supported by  T30.
            // EnableJtag is deprecated as of T210.
            // Send a response but don't stall.
            return  SendResponse(NvBootRcmResponse_UnsupportedOpcode);

        case NvBootRcmOpcode_DownloadExecute:

            e = NvBootValidateEntryPoint(NVBOOT_BL_IRAM_START, pRcmMsg->PayloadLength, pRcmMsg->Args.DownloadData.EntryPoint);
            if(e != NvBootError_Success)
            {
                HandleError(NvBootRcmResponse_InvalidEntryPoint);
                return NvBootError_ValidationFailure;
            }
            break;
        default:
            /* Invalid opcode */
            HandleError(NvBootRcmResponse_InvalidOpcode);
            return NvBootError_ValidationFailure;
    }
    
    s_State.FirstMessageProcessed = NV_TRUE;
    return NvBootError_Success;
}

/**
 * @retval NvBootError_Success The command executed correctly.
 * @retval Otherwise           There was an error.
 * @retval *AppletDownloaded = NV_TRUE An applet was successfully downloaded
 *                                     and should be run.
 * @retval *AppletDownloaded = NV_FALSE Otherwise.
 */
NvBootError
Execute(NvBootRcmMsg* pRcmMsg, NvBool *AppletDownloaded)
{
    NvBootError  e;

    *AppletDownloaded = NV_FALSE;

    switch (pRcmMsg->Opcode)
    {
        case NvBootRcmOpcode_Sync:
            NV_BOOT_CHECK_ERROR(SendResponse(NvBootRcmResponse_Success));
            break;

        // Fuse programing using RCM is not supported T30.
        // To avoid extra changes to the program logic, these commands
        // need to remain here as NOPs.
        case NvBootRcmOpcode_ProgramFuses:
        case NvBootRcmOpcode_VerifyFuses:
        case NvBootRcmOpcode_ProgramFuseArray:
        case NvBootRcmOpcode_VerifyFuseArray:
        case NvBootRcmOpcode_EnableJtag:
            // Do nothing.
            break;

        case NvBootRcmOpcode_DownloadExecute:
            NV_BOOT_CHECK_ERROR(SendResponse(NvBootRcmResponse_Success));
            Context.BootLoader = (uint8_t*)pRcmMsg->Args.DownloadData.EntryPoint;
            *AppletDownloaded = NV_TRUE;
            break;

        case NvBootRcmOpcode_QueryBootRomVersion:
            NV_BOOT_CHECK_ERROR(SendResponse(NVBOOT_BOOTROM_VERSION));
            break;

        case NvBootRcmOpcode_QueryRcmVersion:
            NV_BOOT_CHECK_ERROR(SendResponse(NVBOOT_RCM_VERSION));
            break;

        case NvBootRcmOpcode_QueryBootDataVersion:
            NV_BOOT_CHECK_ERROR(SendResponse(NVBOOT_BOOTDATA_VERSION));
            break;

        case NvBootRcmOpcode_SetDebugFeatures:
            // NvBootDebugSetDebugFeatures returns NvBootError_Success
            // or NvBootError_ECID_Mismatch. ECID mismatch isn't an "error"
            // per se, the value in SecureDebugControl_Not_ECID_Checked is still
            // set into the debug authentication register but the *_ECID_Checked
            // value is not.
            e = NvBootDebugSetDebugFeatures(&pRcmMsg->UniqueChipId,
                            pRcmMsg->SecureDebugControl_Not_ECID_Checked,
                            pRcmMsg->SecureDebugControl_ECID_Checked);

            if(e == NvBootError_ECID_Mismatch)
            {
                NV_BOOT_CHECK_ERROR(SendResponse(NvBootRcmResponse_ECIDMismatch));
            }
            else
            {
                NV_BOOT_CHECK_ERROR(SendResponse(NvBootRcmResponse_Success));
            }
            break;
        default:
            /* Illegal opcodes should be handled by Validate. */
            HandleError(NvBootRcmResponse_InvalidOpcode);
            return NvBootError_ValidationFailure;
    }

    return NvBootError_Success;
}

static NvBootError ProcessMsgForSecureProvisioning(NvBootRcmMsg *pRcmMsg)
{
    NvBootError e;

    // First, check if we are in factory secure provisioning mode.
    e = NvBootFuseIsSecureProvisioningMode(pRcmMsg->SecProvisioningKeyNum_Insecure);

    if(e == NvBootError_SecProvisioningEnabled)
    {
        // Setup and load FSKP key into crypto engine key slot.
        NvBootCryptoMgrFskpInit(pRcmMsg->SecProvisioningKeyNum_Insecure,
                                (uint8_t *)&pRcmMsg->SecProvisioningKeyWrapKey);
        return NvBootError_SecProvisioningEnabled;
    }
    else
    {
        return e;
    }
}

/* Setup Rcm Port Handlers and call Connect (Enumerate) */
NvBootError NvBootRCMInit(void)
{
    NvBootError e;
    NvBootRCMPort_T   *pRcmPort;

            NvBootWdtReload(WDT_TIMEOUT_VAL_RCM);
    BootInfoTable.BootType = NvBootType_Recovery;

    // Override this only on successful download_execute/download_execute_mb1 command.
    Context.BootLoader = (uint8_t*)NvBootMainNonSecureBootLoader;

    // First let's check if this is debug RCM. If so exit immediately.
    // Not sure if Force RCM through PMC has the debug option so checking again
    // if it is Force RCM through Strap.
    if(!NvBootFuseIsOdmProductionMode() && NvBootStrapIsForceRecoveryMode() && NvBootStrapIsDebugRecoveryMode())
    {
        // Set the reason why Boot ROM is exiting in BIT.
        BootInfoTable.BootType = NvBootType_ExitRcm;
        return NvBootError_RcmDebugRcm;
    }

    e = NvBootRcmSetupPortHandle(RCM_XUSB);
    if(e != NvBootError_Success)
        return e;

    pRcmPort = NvBootRcmGetPortHandle();
    
    // Get Clocks table and set it up
    void *RcmClockTable;
    ClockTableType TableType;
    
    pRcmPort->GetClockTable(&RcmClockTable, &TableType);
    e = NvBootClocksEngine(RcmClockTable, TableType);
    if(e != NvBootError_Success)
        return e;

    e = pRcmPort->Init();
    if(e != NvBootError_Success)
        return e;

    // Enable USB Charger detection.
    NvBootUsbChargingInit();

    e = pRcmPort->Connect(NULL);
    if(e != NvBootError_Success)
        return e;

    pRcmPort->Context.Connected = NV_TRUE;
    return NvBootError_Success;
}

/* Send Unique ID. Should be able to handle cable plug in/out and multiple enumerations */
NvBootError NvBootRCMSendUniqueId(void)
{
    NvBootError e;
    NvBootRCMPort_T   *pRcmPort;

    pRcmPort = NvBootRcmGetPortHandle();

    while(1)
    {
        
        if(!pRcmPort->Context.Connected)
        {
            //reload different timeout value for rcm
            e = pRcmPort->Connect(NULL);
            if(e != NvBootError_Success)
                break;
        }
        e = SendUniqueId();
        if (e == NvBootError_XusbReset)
        {
            // Device got reset from the Host, need to re-enumerate
            pRcmPort->Context.Connected = NV_FALSE;
            continue;
        }
        else
            break;
    }
    return e;
}

/* Rcm Main Loop */
NvBootError NvBootRCMProcessMsgs(void)
{
    NvBootError e;
    NvBool LaunchApplet;
    NvBootRcmMsg *pRcmMsg;
    s_State.FirstMessageProcessed = NV_FALSE;

        /* Main command processing loop. */
    while (1)
    {
        pRcmMsg = ( NvBootRcmMsg *)NVBOOT_RCM_MSG_IRAM_START;
        e = ReceiveMessage(pRcmMsg);
        if(e!=NvBootError_Success)
            return e;

        e = Validate(pRcmMsg);
        if(e != NvBootError_Success)
            return e;

        e = Execute(pRcmMsg, &LaunchApplet);
        if(e != NvBootError_Success)
            return e;

        if (LaunchApplet)
        {
            return NvBootError_Success;
        }
    }
    return e;
}
