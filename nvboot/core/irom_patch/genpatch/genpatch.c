/*
 * Copyright (c) 2007 - 2014 NVIDIA Corporation.  All rights reserved.
 * 
 * NVIDIA Corporation and its licensors retain all intellectual property
 * and proprietary rights in and to this software and related documentation
 * and any modifications thereto.  Any use, reproduction, disclosure or
 * distribution of this software and related documentation without an express
 * license agreement from NVIDIA Corporation is strictly prohibited.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

//#include "../nvboot_irom_patch_local.h"
/* Fuse allocation for patching */
#define MAX_PAYLOAD (2560 >> 5)
/* Size of exception prologue in DWORD */
#define EXCP_PROLOGUE	(0x48 >> 2)

#define IROM_PATCH_C		0x10		// 16 bit
#define IROM_PATCH_C_MASK	0x00070000  // only 3 bits
#define IROM_PATCH_N		0x19		// 25 bit

#define IROM_PATCH_VALID    0x80000000  // VALID bit.
/* Cam Entries set to 16 */
#define MAX_CAM			0x10


#ifndef O_BINARY
#define O_BINARY	0x8000
#endif

#define OFFSET_MASK 0x7FFE

#define DBG_MSG 0

#define START_OFFSET (1 << 14)
#define IROM_PATCH_I		0x16		// 16 bit
#define IROM_PATCH_I_MASK	0xFFC00000

#define VERBOSE_H16 0
#define VERBOSE_H5 0
#define NWORDS 32

static const unsigned int UINT_BITS = 32 ;
static const unsigned int LOG2_UINT_BITS = 5 ;
static const unsigned int INSIDE_UINT_OFFSET_MASK = 0x1F ;

static const unsigned int H16_BITS = 16 ;
static const unsigned int H16_START_OFFSET = 1 << (16 - 2) ;
static const unsigned int H16_PARITY_BIT_INDEX = 16 - 1 ;
static const unsigned int H16_ECC_MASK      = 0x0000FFFFU ;
static const unsigned int H16_PARITY_MASK   = 0x00008000U ;
static const unsigned int H16_H_MASK        = 0x00007FFFU ;

static const unsigned int H5_BITS = 5 ;
static const unsigned int H5_CODEWORD_SIZE = 12 ;
static const unsigned int H5_BIT_OFFSET = 20 ; // the H5 code word is mapped on MSB of a word
static const unsigned int H5_PARITY_BIT_INDEX = 20 + 5 - 1 ;
static const unsigned int H5_CODEWORD_MASK = 0xFFF00000U ; 
static const unsigned int H5_ECC_MASK      = 0x01F00000U ;
static const unsigned int H5_PARITY_MASK   = 0x01000000U ;
static const unsigned int H5_H_MASK        = 0x00F00000U ;

static const unsigned int NO_ERROR = 0 ;
static const unsigned int CORRECTED_ERROR = 1 ;
static const unsigned int UNCORRECTED_ERROR_ODD = 2 ; // calculated syndrome associated with a position outside the buffer itself
static const unsigned int UNCORRECTED_ERROR_EVEN = 3 ;

#define NI_BIT_OFFSET (H5_BIT_OFFSET + H5_BITS) //DEFINED here just to overcome compilation error.. ARUn RAJU

// we use a manual table for the Hamming5 code
static const unsigned int H5SyndromeTable[] = { 0x1, 
                                                      0x2,
                                                      0x4,
                                                      0x8,
                                                      0x0, // position of the parity bit, not included in standard Hamming 
                                                      0x3, // sequential, non zero, non power of two numbers
                                                      0x5,
                                                      0x6,
                                                      0x7,
                                                      0x9,
                                                      0xA,
                                                      0xB } ;

static int Parity( unsigned int *Data, unsigned int N) {
    unsigned int ParityWord, i ;
    ParityWord = Data[0] ;
    for (i=1; i<N; i++) { 
		ParityWord ^= Data[i];
	} 
    ParityWord = (ParityWord & 0x0000FFFF) ^ (ParityWord >> 16) ;
    ParityWord = (ParityWord & 0x000000FF) ^ (ParityWord >>  8) ;
    ParityWord = (ParityWord & 0x0000000F) ^ (ParityWord >>  4) ;
    ParityWord = (ParityWord & 0x00000003) ^ (ParityWord >>  2) ;
    ParityWord = (ParityWord & 0x00000001) ^ (ParityWord >>  1) ;
    return ParityWord ;
}


unsigned int Hamming5Syndrome(unsigned int *Data) {
  unsigned int i, Syndrome;
  // Data is assumed to be passed as present in Fuse, i.e. the ECC word starts at bit H5_BIT_OFFSET
#if DBG_MSG
  printf(" Hamming5Syndrome data %x\n",Data[0]);
#endif
  Syndrome = 0 ;
  for (i=0; i<H5_CODEWORD_SIZE; i++) { 
    if (Data[0] & (1 << (H5_BIT_OFFSET + i))) { Syndrome ^= H5SyndromeTable[i] ; }
  }
  // Return the syndrome aligned to the right offset
  return (Syndrome << H5_BIT_OFFSET) ;
}

unsigned int Hamming5Decode( unsigned int  *Data) {
  unsigned int  CalculatedParity, Syndrome, i, StoredNonH5 ;
  StoredNonH5 = Data[0] & ~H5_CODEWORD_MASK ; // Required for correct parity
  Data[0] &= H5_CODEWORD_MASK ;
  // parity should be even (0)
  CalculatedParity = Parity(Data, 1) ;
  Syndrome = Hamming5Syndrome(Data) >> H5_BIT_OFFSET ;
  Data[0] |= StoredNonH5 ;
  if (Syndrome != 0) {
    if (!CalculatedParity) { 
      return UNCORRECTED_ERROR_EVEN ;
    }
    // decode using the Syndrome table, if we fall through the position associated with the Syndrome does not exist
    for (i=0; i<H5_CODEWORD_SIZE; i++) {
      if (Syndrome == H5SyndromeTable[i]) {
        Data[0] ^= (1 << (i + H5_BIT_OFFSET)) ;
        return CORRECTED_ERROR ; // correctable error
      }
    }
    return UNCORRECTED_ERROR_ODD ;
  }
  if (CalculatedParity) { 
    Data[0] ^= H5_PARITY_MASK ;
    return CORRECTED_ERROR ;
  }
  return NO_ERROR ;
}

void Hamming5Encode( unsigned int *Data) {
  // Zero the ECC positions
  Data[0] &= ~H5_ECC_MASK ;
#if DBG_MSG
		printf("Before H5Enc. Data[0] %x\n",Data[0]);
#endif

  // Insert the syndrome 
#if DBG_MSG
//		  printf(" Hamming5Syndrome output %x\n",temp);
#endif

  Data[0] |= Hamming5Syndrome(Data) ;

#if DBG_MSG
			printf(" Hamming5Syndrome output with Data. %x\n",Data[0]);
#endif
  

  // Insert the parity bit to get even parity overall
  // Real code could merge Syndrome and Parity calculation (one scan)
  Data[0] |= (Parity(Data, 1) << H5_PARITY_BIT_INDEX) ;
#if DBG_MSG
		  printf("H5Enc. parity Data[0] %x\n",Data[0]);
#endif

}


unsigned int Hamming16Syndrome( unsigned int *Data, unsigned int N) {
  unsigned int i, j, Syndrome ;
  // Calculate the syndrome
  Syndrome = 0 ;
  for (i=0; i<N; i++) {
    if (Data[i] != 0) {  // for speed, assuming that many words could be zero
      for (j=0; j<UINT_BITS; j++) {
	if ((Data[i] >> j) & 0x1) Syndrome ^= H16_START_OFFSET + (i * UINT_BITS) + j;
      }
    }
  }
  return Syndrome ;
}

void Hamming16Encode( unsigned int *Data, unsigned int N) {

  // Zero the ECC positions
  Data[0] &= ~H16_ECC_MASK ;

  // Insert the syndrome right aligned in the first word
  Data[0] |= Hamming16Syndrome(Data, N) ;

  // Insert the parity bit to get even parity overall
  // Real code could merge Syndrome and Parity calculation (one scan)
  Data[0] |= (Parity(Data, N) << H16_PARITY_BIT_INDEX) ;
#if DBG_MSG  
  printf(" Parity & Data[0] %x \n",Data[0]);
#endif
}

unsigned int NvBootIRomPatchHamming16Decode
( unsigned int *Data, unsigned int N) {
    unsigned int CalculatedParity, StoredSyndrome, StoredParity, Syndrome, offset, i, j, offset_bits_set ;
    // parity should be even (0)
    CalculatedParity = Parity(Data, N) ;
    StoredSyndrome = Data[0] & H16_H_MASK ;
    StoredParity = Data[0] & H16_PARITY_MASK ;
    Data[0] &= ~H16_ECC_MASK ;
    Syndrome = Hamming16Syndrome(Data, N) ^ StoredSyndrome ;
    Data[0] ^= StoredParity ;
    Data[0] ^= StoredSyndrome ;

    if (Syndrome != 0) {
        if (!CalculatedParity) { 
            return UNCORRECTED_ERROR_EVEN ;
        }
    // error is at bit offset Syndrome - H16_START_OFFSET, can be corrected if in range [H16_BITS, N * UINT_BITS[
    offset = Syndrome - H16_START_OFFSET ;
    i = (offset >> LOG2_UINT_BITS) ;
    if ((offset < H16_BITS) || (offset >= UINT_BITS * N)) { // special case of the Hamming bits themselves, detected by Syndrome (or equivalently offset) being a power of two
        offset_bits_set = 0;
        for (j=0; j<H16_BITS-1; j++) {
            if ((Syndrome >> j) & 1) offset_bits_set++;
        }
        if (offset_bits_set == 1) {
            Data[0] ^= Syndrome ;
            return CORRECTED_ERROR ;
        } 
        else {
            return UNCORRECTED_ERROR_ODD ;
        }
    }
    
    Data[i] ^= (1 << (offset & INSIDE_UINT_OFFSET_MASK)) ;
    return CORRECTED_ERROR ; // correctable error
    }

    if (CalculatedParity) { 
        Data[0] ^= H16_PARITY_MASK ;
        return CORRECTED_ERROR ;
    }
    return NO_ERROR ;
}


struct NvIromPatchTotalBlocks
{
	unsigned int TotalBlocks;
	unsigned int PatchRecordSize;
	unsigned int gRetSize;
	unsigned int gRetCodeStart;
};

struct NvIromPatchBlock
{
	unsigned int Tag;
	unsigned int BlockInstructions;
	unsigned int CamEntries;
	unsigned int CamStart;
	unsigned int CodeStart;
};
int main(int argc, char *argv[]){
    int hFile, errBit, errWord;
    char *fBuf, *sfBuf, *TBuf;
    struct stat stat_buf;
    unsigned int NumOfPatchWords, f = 0, p = 0, C ;
    unsigned int Tag, CodeStart, gcode, TotalBlocks, TotalInstructions;
    unsigned int WrBufIndex =0;
	unsigned int TempN_I, status;
    unsigned int N_I = 0, H5 = 0, FirstH5HammingEncode = 1;
    unsigned int WrBuf[MAX_PAYLOAD] ={0};
    unsigned int tempBuf[MAX_PAYLOAD] ={0};
    struct NvIromPatchTotalBlocks TB = {0};
    struct NvIromPatchBlock Block= {0};
	unsigned int LastWordZero =0;

    if (argc < 2) {
	printf("Usage: genpatch.exe <fcode.bin> -e <bit>\n"
		"	-e	Inject bit error at <bits>\n");
	return 0;
    }  

    hFile = open(argv[1], O_RDONLY | O_BINARY);
    if (hFile == -1){
	printf("ERROR: Cannot open %s.\n", argv[1]);
	return 1;
    }
    fstat(hFile, &stat_buf);

    
    fBuf = (char *)malloc(stat_buf.st_size);
    if (fBuf == NULL){
	printf("ERROR: malloc() failed.\n");
	return 1;
    }

    TBuf = sfBuf = fBuf; //save for closing..
    memset(fBuf, 0, stat_buf.st_size);
    read(hFile, fBuf, stat_buf.st_size);
    close(hFile);

	//copy TotalBlock information
	memcpy((char *)(&TB), fBuf, (unsigned int)(sizeof(struct NvIromPatchTotalBlocks)));
	fBuf += sizeof(struct NvIromPatchTotalBlocks);
#if DBG_MSG	
	printf(" ************************************************************************************************************\n");
	printf("Total Block information \n");
	printf("Number of patch records %x \n",TB.TotalBlocks);
	printf("PatchRecordSize %x \n",TB.PatchRecordSize);
	printf("ReturnInstSize %x \n",TB.gRetSize);
	printf("ReturnCodeStart %x \n",TB.gRetCodeStart);
	printf("Actual ReturnCodeStart %x \n",TB.gRetCodeStart & OFFSET_MASK);
	printf("TotalBlock Hsize %x  \n",sizeof(struct NvIromPatchTotalBlocks));
	printf("patchblockheadersize %x  \n",sizeof(struct NvIromPatchBlock));
	printf("Actual payload %x  \n",	(TB.TotalBlocks + TB.PatchRecordSize -  (sizeof(struct NvIromPatchTotalBlocks) + (TB.TotalBlocks * sizeof(struct NvIromPatchBlock)))/4));
	printf(" ************************************************************************************************************\n");

	printf("fbuf %x \n",fBuf);
	printf("sfBuf %x \n",sfBuf);
	printf("WrBuf %x \n",WrBuf);
#endif

	// allocate buffer for complete patch record.
	if(TB.TotalBlocks && TB.PatchRecordSize)
	{
		if((TB.TotalBlocks + TB.PatchRecordSize -  (sizeof(struct NvIromPatchTotalBlocks) + (TB.TotalBlocks * sizeof(struct NvIromPatchBlock)))/4) > MAX_PAYLOAD){
		printf("ERROR: recordSize greater then payload supported. %x \n",TB.PatchRecordSize);
		return 1;
		} 
	}
	while(TB.TotalBlocks)
	{	
		TBuf = (sfBuf + sizeof(struct NvIromPatchTotalBlocks));//reset
		TotalBlocks = TB.TotalBlocks;
#if DBG_MSG	
		printf("TBuf %x \n",TBuf);
		printf("TotalBlocks %x \n",TotalBlocks);
#endif
		//locate last/new tag block
		while(TotalBlocks != 1)
		{
			memcpy((char *)(&Block), TBuf, (unsigned int)(sizeof(struct NvIromPatchBlock)));
			TBuf += sizeof(struct NvIromPatchBlock);
			TBuf += (Block.CamEntries * sizeof(unsigned int));
			TotalBlocks--;
		}

#if DBG_MSG	
		printf("TBuf %x \n",TBuf);
#endif
		fBuf = TBuf;
		//copy Block0 information
		memcpy((char *)(&Block), fBuf, (unsigned int)(sizeof(struct NvIromPatchBlock)));
		if(!(Block.CamEntries + Block.BlockInstructions)) 
			break;
		fBuf += sizeof(struct NvIromPatchBlock);
#if DBG_MSG
		printf(" ************************************************************************************************************\n");
		printf("Block information \n");
		printf("Tag %x \n",Block.Tag);
		printf("patch instructions %x \n",Block.BlockInstructions);
		printf("Cam Entries %x \n",Block.CamEntries);
		printf("CAM Start offset @ %x \n",Block.CamStart);
		printf("Actual CAM Start offset @ %x \n",Block.CamStart & OFFSET_MASK);
		printf("Code Start offset @ %x \n",Block.CodeStart);
		printf("Actual Code Start offset @ %x \n",Block.CodeStart & OFFSET_MASK);
		printf("fbuf %x \n",fBuf);
		printf(" ************************************************************************************************************\n");
#endif

		//cam entries.
		C = Block.CamEntries;//  usage is Cam entries == C + 1, make NOTE ARUN RAju

		if(TB.TotalBlocks == 1)
		{
		    // N[i] = I[i] + C[i] + 1 + E[i] + 1
		    NumOfPatchWords = Block.CamEntries + Block.BlockInstructions + TB.gRetSize + 1 ;//+ 1
//			N_I = Block.BlockInstructions + TB.gRetSize; 
		}
		else
		{
		    NumOfPatchWords = Block.CamEntries + Block.BlockInstructions + 1; //+1?
//			N_I = Block.BlockInstructions;
		}
			

#if DBG_MSG
		printf("NumOfPatchWords %x \n",NumOfPatchWords);
#endif

	    if (C > MAX_CAM){
		free(fBuf);
		printf("ERROR: CAM entries more than MAX_CAM.\n");
		return 1;
	    }
	    if (NumOfPatchWords > MAX_PAYLOAD){
		free(fBuf);
		printf("ERROR: Patch size exceeds MAX_PAYLOAD.\n");
		return 1;
	    }

#if DBG_MSG	
		printf("fbuf %x \n",fBuf);
		printf("tempBuf %x \n",tempBuf);
 		for (p = 0; p < Block.CamEntries; p++)//NumOfPatchWords
		{
			printf("fBuf Cam[%d] %x \n",p,((unsigned int *)fBuf)[p]);
		}
		printf("fbuf %x \n",fBuf);
#endif

		//copy cam entries
		//leave first word blank
		memcpy((char *)(&tempBuf[1]), fBuf, sizeof(unsigned int) * (Block.CamEntries + 1));
		
#if DBG_MSG	
		printf("block.CodeStart %x \n",(sfBuf + (Block.CodeStart & OFFSET_MASK)));
#endif
		//copy svc handler
		memcpy((char *)(&tempBuf[Block.CamEntries + 1]), (sfBuf + (Block.CodeStart & OFFSET_MASK)), sizeof(unsigned int) * (Block.BlockInstructions));

		//copy common return branch "g_code_end".
		if(TB.TotalBlocks == 1)
			memcpy((char *)(&tempBuf[Block.CamEntries + Block.BlockInstructions + 1]), (sfBuf + (TB.gRetCodeStart & OFFSET_MASK)), sizeof(unsigned int) * (TB.gRetSize));
		
		//update 
#if DBG_MSG
		printf("tempBuf %x \n",tempBuf);
 		for (p = 0; p < (NumOfPatchWords); p++)
		{
			printf("tempBuf[%d] %x \n",p,((unsigned int *)tempBuf)[p]);
		}
#endif


		// update Cam entry
	    *(unsigned int *)(tempBuf) = ((C - 1) << IROM_PATCH_C); //usage is Cam entries == C + 1, make NOTE ARUN RAju //| (0x333 << IROM_PATCH_I


//		printf(" NumOfPatchWords %x \n",NumOfPatchWords);
		Hamming16Encode((unsigned int *)tempBuf, NumOfPatchWords);

//		status = NvBootIRomPatchHamming16Decode((unsigned int *)tempBuf, NumOfPatchWords);
//    if(status > 0)
//	printf(" NvBootIRomPatchHamming16Decode %x \n",status);
#if DBG_MSG
#if 0
	for (p = 0; p < 9; p++)
		{
		printf("input value %x \n",p);
		N_I = p << NI_BIT_OFFSET ;
        Hamming5Encode(&N_I);
		printf("output H5encode value %x \n",N_I);

		}
	#endif
#endif
		if(!FirstH5HammingEncode)
		{

#if DBG_MSG
			printf("NumOfPatchWords %x \n",NumOfPatchWords);
#endif

#if DBG_MSG
			printf(" H5 %x \n",N_I);
#endif

			// Hamming5Encode for NumOfPatchWords
		    N_I = (NumOfPatchWords & 0x00000FFF) << NI_BIT_OFFSET;
#if DBG_MSG
    		printf(" H5 %x \n",N_I);
#endif

			Hamming5Encode(&N_I);
         TempN_I = N_I;
            status = Hamming5Decode(&TempN_I);
#if DBG_MSG
			printf("Hammnig DecodeH5 %x \n",status);
			printf("Last Hammnig Encode H5 %x \n",N_I);
#endif
		//update FirstH5 entry..		
		FirstH5HammingEncode++;
		}else{
			FirstH5HammingEncode++;

		
#if DBG_MSG
					printf("NumOfPatchWords %x \n",NumOfPatchWords);
#endif

			// Hamming5Encode for NumOfPatchWords
//		    N_I = (N_I & 0x00000FFF) << NI_BIT_OFFSET;

#if DBG_MSG
						printf(" H5 %x \n",N_I);
#endif
			TempN_I = NumOfPatchWords;
            NumOfPatchWords = NumOfPatchWords << NI_BIT_OFFSET ;
			Hamming5Encode(&NumOfPatchWords);
//            status = Hamming5Decode(&TempN_I);
#if DBG_MSG
//			printf("Hammnig DecodeH5 %x \n",status);
					printf("NumOfPatchWords after H5Encode %x \n",NumOfPatchWords);
					printf("Header of current patch record %x \n",*tempBuf);
#endif
		//update H5 to IromPatch Header with H16
		*(unsigned int *)(tempBuf) |= (NumOfPatchWords);

#if DBG_MSG
					printf("tempBuf with H5 and N[I] of prev block %x \n",*tempBuf);
#endif
		}

//				status = NvBootIRomPatchHamming16Decode((unsigned int *)tempBuf, TempN_I);
//			  if(status > 0)
//			printf(" NvBootIRomPatchHamming16Decode %x \n",status);

		//restore NumOfPatchWords
		NumOfPatchWords = TempN_I;
		
	    if (argc > 3){
		if (!strcmp(argv[2], "-e")){
		    if (sscanf(argv[3], "%d", &errBit) == 1){
			printf("/*\nINFO: Single-bit error injected at bit %d.\n*/\n", errBit);
			errWord = errBit / 8;
			errBit %= 8;
			tempBuf[errWord] ^= (0x1 << errBit);
			
		    }
		}
	    }

#if DBG_MSG
	    for (p = 0; p < NumOfPatchWords; p++)
		{
			printf("Hammed tempBuf[%d] %x \n",p,((unsigned int *)tempBuf)[p]);
		}
#endif

		f = 0;
#if DBG_MSG
			printf("p %d , f %d, WrBufIndex %d \n",p,f, WrBufIndex);
 			printf("WrBuf %x , WrBufIndex %d tempBuf %x\n",WrBuf, WrBufIndex,tempBuf);
#endif

	    for (p = (WrBufIndex + NumOfPatchWords); p > WrBufIndex ; p--)
    	{
 			WrBuf[p - 1] = tempBuf[f++];
    	}

#if DBG_MSG
	    for (p = WrBufIndex; p < WrBufIndex + NumOfPatchWords; p++)
		{
			printf("Dump WrBuf[%d] %x \n",p,((unsigned int *)WrBuf)[p]);
		}
#endif
		WrBufIndex += NumOfPatchWords;
  		fBuf += (Block.CamEntries * sizeof(unsigned int));
 		TB.TotalBlocks--;//decrement patch record count.
	}
    free(sfBuf);

    hFile = open(argv[1], O_WRONLY | O_TRUNC | O_BINARY);
    write(hFile, WrBuf, sizeof(unsigned int) * WrBufIndex);
    close(hFile);

    printf("/* Generated by genpatch. */\n");
    printf("#define FIRST_PATCH_SIZE 0x%X\n", NumOfPatchWords);
    printf("#define FCODE_HEADER 0x%X\n", WrBufIndex-1);
    printf("static const unsigned int fcode[] = {\n");
	printf("	0x%08X,\n", ((unsigned int *)LastWordZero));
    for (p = 0; p < WrBufIndex; p++)
        printf("    0x%08X,\n", ((unsigned int *)WrBuf)[p]);
    printf("};\n/* Generated by genpatch. */\n");
    return 0;
}
