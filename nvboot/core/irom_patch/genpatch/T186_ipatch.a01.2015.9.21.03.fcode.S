	AREA	|.text|, CODE
    CODE16
;===========================================================================
; Total blocks
	DCD 0x3; total blocks
	DCD	 b_inst_cnt
	DCD	 g_ins_cnt
	DCD g0_code_start
b_inst_start
;===========================================================================
; Tag Block
    DCB "$CP$"
    DCD b0_ins_cnt	; patch svc/instruction count
    DCD b0_cam_cnt	; patch cam entries
    DCD b0_cam_start	; Pointer to cam entries block
    DCD b0_code_start	; Pointer to svc/instruction block

;===========================================================================
; CAM register entries. Up to 12 entries
b0_cam_start	
    DCD 0x5499df00  ; svc #00 	(@1a932 ) ((1a932 - 10000) >>1 == 5499)
b0_cam_cnt EQU ((. - b0_cam_start)/4)

;===========================================================================
; Tag Block
    DCB "$CP$"
    DCD b1_ins_cnt	; patch svc/instruction count
    DCD b1_cam_cnt	; patch cam entries
    DCD b1_cam_start	; Pointer to cam entries block
    DCD b1_code_start	; Pointer to svc/instruction block

;===========================================================================
b1_cam_start	
    DCD 0x49E9df06  ; svc #01 	(@193d2 ) ((193d2 - 10000) >>1 == 49E9)
    DCD 0x4906df13  ; svc #02 	(@1920c ) ((1920c - 10000) >>1 == 4906)
b1_cam_cnt EQU ((. - b1_cam_start)/4)

;===========================================================================
; Tag Block
    DCB "$CP$"
    DCD b2_ins_cnt	; patch svc/instruction count
    DCD b2_cam_cnt	; patch cam entries
    DCD b2_cam_start	; Pointer to cam entries block
    DCD b2_code_start	; Pointer to svc/instruction block

;===========================================================================
; CAM register entries. Up to 12 entries
b2_cam_start	
    DCD 0x0924df2e  ; svc #03 	(@11248 ) ((11248 - 10000) >>1 == 924)
    DCD 0x03A0f440	; data patch @ 10740  ((10740 - 10000) >>1 == 3A0)
b2_cam_cnt EQU ((. - b2_cam_start)/4)

b0_code_start
	CODE16
;SVC #00
	mov	r2, #0x20	;to set bit 25, mov immediate 20
	lsl	r2, #0x14	; lshift 20
	orr	r0, r2		; setting TERM
	orrs	r0, r4		; replace instruction here..//   1a932:	4320      	orrs	r0, r4
;    b   	g_code_end
   LTORG       ;Literals within the same block
b0_ins_cnt EQU ((. - b0_code_start)/4)

g0_code_start
g_code_end
	CODE16
	pop	{r2}
	mov	pc, lr
g_ins_cnt EQU ((. - g0_code_start)/4)

b1_code_start
	CODE16
;SVC #01
	ldr r2,=0x3820100 
	ldr r3, [r2]		; Read Production Fuse
	add r2, r2, #0xec
						; Read FUSE_SECURE_PROVISION_INFO_0
	ldr r1, [r2]
	orr r1,r1,r3		; OR production and test fuse to get production mode.
	
	ldr r2,=0xd480000
	ldr r3, [r2,#0x18]	; Read Boot Security Info
	lsl r1,r1, #0x3		; Move Production mode to Bit 3
	orr r1,r1, r3		; OR with Boot auth Info
	ldrb r3, [r2, #0x1c]	; 
	lsl	r3,r3, #0x2		; shift ?
	orr r1,r1, r3		; OR with Boot encryption Info
    b   	g_code_end

;SVC #02
	ldr r2,=0x38201a0 ; load production fuse base.
	ldr r4, [r2] ; load security fuse into r4
	cmp r4,#0x1;   check if 1; 
	beq disable ; if 1, disable download execute immediately, otherwise check other conditions
	ldr r4,=0xc360070 ; load pmc rst status
	ldr r4,[r4] ; read
	lsr r4 , #2 ; get RST_SOURCE
	;and r4,r4, #0x3c ; mask and get RST_SOURCE [5:2]
	cmp r4, #0 ; check if sys_rst_n   
	beq end ; if yes, it means security=0 AND coldboot, good enough, Don’t disable
    sub r2, #0xa0
	ldr r2,[r2]; Read production fuse if rst_source is NOT sys_rst_n
	cmp r2, #0x1 ; check production fuse
	bne end ; not coldboot not production = preproduction; do nothing
disable mov r3, #0 ; corrupt r3 to cause failure
end
	mov r2, sp ; 
	ldr r2, [r2]
	cmp r3, r2; CPSR bits set. Now we can return to BHI instruction
    b   	g_code_end
   LTORG       ;Literals within the same block
b1_ins_cnt EQU ((. - b1_code_start)/4)


b2_code_start
	CODE16
;SVC #03
	ldr r2,=0x0c360070 
	ldr r2, [r2]		; Read RST_STATUS
	mov r0, #0x03		; set for mask
	and r2, r0			; mask RST_LEVEL
	tst r2, r0			; Check for WARM RST_LEVEL
	bne l1reset
	mov r0, #0x1
l1reset	
	adds r0, #0			; replacement entry.	
    b   	g_code_end
   LTORG       ;Literals within the same block
b2_ins_cnt EQU ((. - b2_code_start)/4)

;===========================================================================
; End of Blocks
b_inst_cnt EQU ((. - b_inst_start)/4)
;===========================================================================
	END



