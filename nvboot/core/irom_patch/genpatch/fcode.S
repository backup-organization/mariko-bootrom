	AREA	|.text|, CODE
    CODE16
;===========================================================================
; Total blocks
	DCD 0x2	; total blocks
	DCD	 b_inst_cnt
	DCD	 g_ins_cnt
	DCD g0_code_start
b_inst_start
;===========================================================================
; Tag Block
    DCB "$CP$"
    DCD b0_ins_cnt		; patch svc/instruction count
    DCD b0_cam_cnt	; patch cam entries
    DCD b0_cam_start	; Pointer to cam entries block
    DCD b0_code_start	; Pointer to svc/instruction block

;===========================================================================
; CAM register entries. Up to 12 entries
b0_cam_start	
    DCD 0x105B2315  ; data replace #00 	(@120b6 ) ((120b6 - 10000) >>1 == 105B)
    DCD 0x10682001  ; data replace @ 120d0, ((120d0 - 10000)) >> 1 = 1068) 
b0_cam_cnt EQU ((. - b0_cam_start)/4)

;===========================================================================
; Tag Block
    DCB "$CP$"
    DCD b1_ins_cnt		; patch svc/instruction count
    DCD b1_cam_cnt	; patch cam entries
    DCD b1_cam_start	; Pointer to cam entries block
    DCD b1_code_start	; Pointer to svc/instruction block

;===========================================================================
; CAM register entries. Up to 12 entries
b1_cam_start	
    DCD 0x035Ddf08  	; SVC #00 	(@ 106ba ) ((106ba  - 10000) >> 1 = 35D
b1_cam_cnt EQU ((. - b1_cam_start)/4)

b0_code_start
	CODE16
;SVC #00
    ldr		r2,=0xffffffff
    mov		r0, #0xe      	; instruction replaced @0x001016ae
    b   	g_code_end
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
;SVC #00
    ; populate r0-r8
    ;r1
    ldr 		r0,=0x00000001
    str	       r0, [sp, #0]		;value for r1    
    ldr 		r0,=0x00000002
    str	       r0, [sp, #0]		;value for r2   
    ldr 		r0,=0x00000003
    str	       r0, [sp, #0]		;value for r3    
    ldr 		r0,=0x00000004
    str	       r0, [sp, #0]		;value for r4    
    ldr 		r0,=0x00000005
    str	       r0, [sp, #0]		;value for r5    
    ldr 		r0,=0x00000006
    str	       r0, [sp, #0]		;value for r6    
    ldr 		r0,=0x00000007
    str	       r0, [sp, #0]    		;value for r7    
    ldr 		r3,=0x12345678 	;value for r0 (same instruction is being replaced)
    b   	g_code_end
   LTORG       ;Literals within the same block
b1_ins_cnt EQU ((. - b1_code_start)/4)

;===========================================================================
; End of Blocks
b_inst_cnt EQU ((. - b_inst_start)/4)
;===========================================================================
	END


