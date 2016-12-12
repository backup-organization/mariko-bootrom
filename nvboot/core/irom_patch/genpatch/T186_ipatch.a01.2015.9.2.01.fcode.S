	AREA	|.text|, CODE
    CODE16
;===========================================================================
; Total blocks
	DCD 0x1	; total blocks
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
    DCD 0x5499df00  ; svc #00 	(@1a932 ) ((1a932 - 10000) >>1 == 5499)
b0_cam_cnt EQU ((. - b0_cam_start)/4)


b0_code_start
	CODE16
;SVC #00
	mov	r2, #0x20	;to set bit 25, mov immediate 20
	lsl	r2, #0x14	; lshift 20
	orr	r0, r2		; setting TERM
	orrs	r0, r4		; replace instruction here..//   1a932:	4320      	orrs	r0, r4
    b   	g_code_end
   LTORG       ;Literals within the same block
b0_ins_cnt EQU ((. - b0_code_start)/4)

g0_code_start
g_code_end
	CODE16
	pop	{r2}
	mov	pc, lr
g_ins_cnt EQU ((. - g0_code_start)/4)

;===========================================================================
; End of Blocks
b_inst_cnt EQU ((. - b_inst_start)/4)
;===========================================================================
	END


