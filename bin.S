#
# test file
#
.text


knownbugs:
	nop

objdump_bug:
	msr	dbgdtrtx_el0, x0
	mrs	x0, dbgdtrrx_el0

objdump_dif:
	mov	w1, #0x20002
	mov	w8, #0x10001
	.word	0x0d508711f & ~1

testpattern:
	orr	x10, xzr, #0x100000000
	orr	x10, xzr, #0xfff00000000
	orr	x10, xzr, #0xfff000000000
	orr	x10, xzr, #0xfff0000000000
	orr	x10, xzr, #0xfff00000000000
	orr	x10, xzr, #0xfff000000000000
	orr	x10, xzr, #0xfff0000000000000
	nop

	isb
	isb	#0
	isb	#1
	isb	#2
	isb	#3
	isb	#13
	isb	#14
	isb	#15

	ldrh	w2, [x25,w8,uxtw]
	ldrsh	w9, [x21],#2
	ldrsh	w8, [x20,#170]!
	ldrsh	w9, [x8,#40]!
	ldrsh	w8, [x27,#2]!
	ror	w15, w16, w15
	ror	w11, w11, w12
	strh	w11, [x22,w10,sxtw]
	strh	w0, [x8,w1,uxtw]
	stxr	w3, x0, [x4]
	stxrb	w11, w9, [x8]
	stxrh	w3, w2, [x4]

	hint	#0
	hint	#1
	hint	#2
	hint	#3
	hint	#4
	hint	#5
	hint	#6
	hint	#7
	hint	#8
	hint	#100

	sys	#0, C0, C0, #0, x0

	ldrsw	x28, [x8,x27,lsl #2]
	ldrsw	x9, [x20,x8]
	nop

	and	w9, w22, #0x10001
	cmp	w10, #0xfff
	cmp	w9, #0xf01
	ldr	w8, [x19,#12608]
	ldrsw	x21, [x20,#24]!
	mov	x8, #0xffff1000ffffffff
	rev16	w0, w0
	smaddl	x25, w8, w27, x22
	smaddl	x28, w8, w10, x26
	smull	x8, w0, w8
	smull	x8, w8, w9
	str	w8, [x19,#12608]
	str	xzr, [x20,#32728]
	sub	w11, w1, #0x9c4

	ldrh	w10, [x25,#50]!
	ldrb	w9, [x26,#116]!
	ldur	x8, [x26,#12]

	sxtw	x20, w20
	umull	x8, w0, w24
	sdiv	w19, w10, w8

	mov	x9, #0x4000400040004
	mov	x9, #0x700000007

	ldar	w1, [x5]
	ldar	w2, [x6,#0]
	ldar	x3, [x7]
	ldar	x4, [x8,#0]

	crc32b	w0, w1, w2
	crc32x	w0, w1, x2
	crc32cb	w0, w1, w2
	crc32cx	w0, w1, x2

	ldr	x1, [sp, x0, lsl #0]
	ldr	w2, [sp, x0, lsl #0]
	ldrb	w0, [sp, x0, lsl #0]
	ldrb	w0, [sp, w0, uxtw]
	ldrb	w0, [sp, w0, uxtw #0]


	prfm	PLDL1KEEP, [x0, x1]
	prfm	PLDL1KEEP, [x0, x1, lsl #0]
	prfm	PLDL1KEEP, [x0, x1, lsl #3]
	prfm	PLDL1KEEP, [x0, w1, uxtw #0]
	prfm	PLDL1KEEP, [x0, w1, uxtw #3]
	prfm	PLDL1KEEP, [x0, w1, sxtw #0]
	prfm	PLDL1KEEP, [x0, w1, sxtw #3]
	prfm	PLDL1KEEP, [x0, x1, sxtx]
	prfm	PLDL1KEEP, [x0, x1, sxtx]
	prfm	PLDL1KEEP, [x0, x1, sxtx #3]
	prfm	PLDL1KEEP, [x0, x1, sxtx #3]

	prfm	PLDL1KEEP, [x0, xzr]
	prfm	PLDL1KEEP, [x0, xzr, lsl #0]
	prfm	PLDL1KEEP, [x0, xzr, lsl #3]
	prfm	PLDL1KEEP, [x0, wzr, uxtw #0]
	prfm	PLDL1KEEP, [x0, wzr, uxtw #3]
	prfm	PLDL1KEEP, [x0, wzr, sxtw #0]
	prfm	PLDL1KEEP, [x0, wzr, sxtw #3]
	prfm	PLDL1KEEP, [x0, xzr, sxtx]
	prfm	PLDL1KEEP, [x0, xzr, sxtx]
	prfm	PLDL1KEEP, [x0, xzr, sxtx #3]
	prfm	PLDL1KEEP, [x0, xzr, sxtx #3]


	asr	w24, w10, #1
	asr	w24, w10, #2
	asr	w24, w10, #3
	asr	w24, w10, #4
	asr	w24, w10, #5
	asr	w24, w10, #31
	asr	x24, x10, #32
	asr	x24, x10, #33
	asr	x24, x10, #34
	asr	x24, x10, #35
	asr	x24, x10, #36
	asr	x24, x10, #60
	asr	x24, x10, #61
	asr	x24, x10, #62
	asr	x24, x10, #63

	ic	IALLUIS
	ic	IALLUIS

	msr	SPsel, #1
	msr	DAIFset, #10
	msr	DAIFclr, #15

	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1
	mrs	x9, ccsidr_el1

	mrs	x9, osdtrrx_el1
	mrs	x9, dbgbvr0_el1
	mrs	x9, dbgbcr0_el1
	mrs	x9, dbgwvr0_el1
	mrs	x9, dbgwcr0_el1
	mrs	x9, dbgbvr1_el1
	mrs	x9, dbgbcr1_el1
	mrs	x9, dbgwvr1_el1
	mrs	x9, dbgwcr1_el1
	mrs	x9, mdccint_el1
	mrs	x9, mdscr_el1
	mrs	x9, dbgbvr2_el1
	mrs	x9, dbgbcr2_el1
	mrs	x9, dbgwvr2_el1
	mrs	x9, dbgwcr2_el1
	mrs	x9, osdtrtx_el1
	mrs	x9, dbgbvr3_el1
	mrs	x9, dbgbcr3_el1
	mrs	x9, dbgwvr3_el1
	mrs	x9, dbgwcr3_el1
	mrs	x9, dbgbvr4_el1
	mrs	x9, dbgbcr4_el1
	mrs	x9, dbgwvr4_el1
	mrs	x9, dbgwcr4_el1
	mrs	x9, dbgbvr5_el1
	mrs	x9, dbgbcr5_el1
	mrs	x9, dbgwvr5_el1
	mrs	x9, dbgwcr5_el1
	mrs	x9, oseccr_el1
	mrs	x9, dbgbvr6_el1
	mrs	x9, dbgbcr6_el1
	mrs	x9, dbgwvr6_el1
	mrs	x9, dbgwcr6_el1
	mrs	x9, dbgbvr7_el1
	mrs	x9, dbgbcr7_el1
	mrs	x9, dbgwvr7_el1
	mrs	x9, dbgwcr7_el1
	mrs	x9, dbgbvr8_el1
	mrs	x9, dbgbcr8_el1
	mrs	x9, dbgwvr8_el1
	mrs	x9, dbgwcr8_el1
	mrs	x9, dbgbvr9_el1
	mrs	x9, dbgbcr9_el1
	mrs	x9, dbgwvr9_el1
	mrs	x9, dbgwcr9_el1
	mrs	x9, dbgbvr10_el1
	mrs	x9, dbgbcr10_el1
	mrs	x9, dbgwvr10_el1
	mrs	x9, dbgwcr10_el1
	mrs	x9, dbgbvr11_el1
	mrs	x9, dbgbcr11_el1
	mrs	x9, dbgwvr11_el1
	mrs	x9, dbgwcr11_el1
	mrs	x9, dbgbvr12_el1
	mrs	x9, dbgbcr12_el1
	mrs	x9, dbgwvr12_el1
	mrs	x9, dbgwcr12_el1
	mrs	x9, dbgbvr13_el1
	mrs	x9, dbgbcr13_el1
	mrs	x9, dbgwvr13_el1
	mrs	x9, dbgwcr13_el1
	mrs	x9, dbgbvr14_el1
	mrs	x9, dbgbcr14_el1
	mrs	x9, dbgwvr14_el1
	mrs	x9, dbgwcr14_el1
	mrs	x9, dbgbvr15_el1
	mrs	x9, dbgbcr15_el1
	mrs	x9, dbgwvr15_el1
	mrs	x9, dbgwcr15_el1
	mrs	x9, mdrar_el1
	mrs	x9, oslsr_el1
	mrs	x9, osdlr_el1
	mrs	x9, dbgprcr_el1
	mrs	x9, dbgclaimset_el1
	mrs	x9, dbgclaimclr_el1
	mrs	x9, dbgauthstatus_el1
	mrs	x9, teecr32_el1
	mrs	x9, teehbr32_el1
	mrs	x9, mdccsr_el0
	mrs	x9, dbgdtr_el0
//	mrs	x9, dbgdtrrx_el0
	mrs	x9, dbgvcr32_el2
	mrs	x9, midr_el1
	mrs	x9, mpidr_el1
	mrs	x9, revidr_el1
	mrs	x9, id_pfr0_el1
	mrs	x9, id_pfr1_el1
	mrs	x9, id_dfr0_el1
	mrs	x9, id_afr0_el1
	mrs	x9, id_mmfr0_el1
	mrs	x9, id_mmfr1_el1
	mrs	x9, id_mmfr2_el1
	mrs	x9, id_mmfr3_el1
	mrs	x9, id_isar0_el1
	mrs	x9, id_isar1_el1
	mrs	x9, id_isar2_el1
	mrs	x9, id_isar3_el1
	mrs	x9, id_isar4_el1
	mrs	x9, id_isar5_el1
	mrs	x9, mvfr0_el1
	mrs	x9, mvfr1_el1
	mrs	x9, mvfr2_el1
	mrs	x9, id_aa64pfr0_el1
	mrs	x9, id_aa64pfr1_el1
	mrs	x9, id_aa64dfr0_el1
	mrs	x9, id_aa64dfr1_el1
	mrs	x9, id_aa64afr0_el1
	mrs	x9, id_aa64afr1_el1
	mrs	x9, id_aa64isar0_el1
	mrs	x9, id_aa64isar1_el1
	mrs	x9, id_aa64mmfr0_el1
	mrs	x9, id_aa64mmfr1_el1
	mrs	x9, ccsidr_el1
	mrs	x9, clidr_el1
	mrs	x9, aidr_el1
	mrs	x9, csselr_el1
	mrs	x9, ctr_el0
	mrs	x9, dczid_el0
	mrs	x9, vpidr_el2
	mrs	x9, vmpidr_el2
	mrs	x9, sctlr_el1
	mrs	x9, actlr_el1
	mrs	x9, cpacr_el1
	mrs	x9, sctlr_el2
	mrs	x9, actlr_el2
	mrs	x9, hcr_el2
	mrs	x9, mdcr_el2
	mrs	x9, cptr_el2
	mrs	x9, hstr_el2
	mrs	x9, hacr_el2
	mrs	x9, sctlr_el3
	mrs	x9, actlr_el3
	mrs	x9, scr_el3
	mrs	x9, sder32_el3
	mrs	x9, cptr_el3
	mrs	x9, mdcr_el3
	mrs	x9, ttbr0_el1
	mrs	x9, ttbr1_el1
	mrs	x9, tcr_el1
	mrs	x9, ttbr0_el2
	mrs	x9, tcr_el2
	mrs	x9, vttbr_el2
	mrs	x9, vtcr_el2
	mrs	x9, ttbr0_el3
	mrs	x9, tcr_el3
	mrs	x9, dacr32_el2
	mrs	x9, spsr_el1
	mrs	x9, elr_el1
	mrs	x9, sp_el0
	mrs	x9, spsel
	mrs	x9, currentel
	mrs	x9, nzcv
	mrs	x9, daif
	mrs	x9, fpcr
	mrs	x9, fpsr
	mrs	x9, dspsr_el0
	mrs	x9, dlr_el0
	mrs	x9, spsr_el2
	mrs	x9, elr_el2
	mrs	x9, sp_el1
	mrs	x9, spsr_irq
	mrs	x9, spsr_abt
	mrs	x9, spsr_und
	mrs	x9, spsr_fiq
	mrs	x9, spsr_el3
	mrs	x9, elr_el3
	mrs	x9, sp_el2
	mrs	x9, afsr0_el1
	mrs	x9, afsr1_el1
	mrs	x9, esr_el1
	mrs	x9, ifsr32_el2
	mrs	x9, afsr0_el2
	mrs	x9, afsr1_el2
	mrs	x9, esr_el2
	mrs	x9, fpexc32_el2
	mrs	x9, afsr0_el3
	mrs	x9, afsr1_el3
	mrs	x9, esr_el3
	mrs	x9, far_el1
	mrs	x9, far_el2
	mrs	x9, hpfar_el2
	mrs	x9, far_el3
	mrs	x9, par_el1
	mrs	x9, pmintenset_el1
	mrs	x9, pmintenclr_el1
	mrs	x9, pmcr_el0
	mrs	x9, pmcntenset_el0
	mrs	x9, pmcntenclr_el0
	mrs	x9, pmovsclr_el0
	mrs	x9, pmselr_el0
	mrs	x9, pmceid0_el0
	mrs	x9, pmceid1_el0
	mrs	x9, pmccntr_el0
	mrs	x9, pmxevtyper_el0
	mrs	x9, pmxevcntr_el0
	mrs	x9, pmuserenr_el0
	mrs	x9, pmovsset_el0
	mrs	x9, mair_el1
	mrs	x9, amair_el1
	mrs	x9, mair_el2
	mrs	x9, amair_el2
	mrs	x9, mair_el3
	mrs	x9, amair_el3
	mrs	x9, vbar_el1
	mrs	x9, rvbar_el1
	mrs	x9, rmr_el1
	mrs	x9, isr_el1
	mrs	x9, vbar_el2
	mrs	x9, rvbar_el2
	mrs	x9, rmr_el2
	mrs	x9, vbar_el3
	mrs	x9, rvbar_el3
	mrs	x9, rmr_el3
	mrs	x9, contextidr_el1
	mrs	x9, tpidr_el1
	mrs	x9, tpidr_el0
	mrs	x9, tpidrro_el0
	mrs	x9, tpidr_el2
	mrs	x9, tpidr_el3
	mrs	x9, cntkctl_el1
	mrs	x9, cntfrq_el0
	mrs	x9, cntpct_el0
	mrs	x9, cntvct_el0
	mrs	x9, cntp_tval_el0
	mrs	x9, cntp_ctl_el0
	mrs	x9, cntp_cval_el0
	mrs	x9, cntv_tval_el0
	mrs	x9, cntv_ctl_el0
	mrs	x9, cntv_cval_el0
	mrs	x9, pmevcntr0_el0
	mrs	x9, pmevcntr1_el0
	mrs	x9, pmevcntr2_el0
	mrs	x9, pmevcntr3_el0
	mrs	x9, pmevcntr4_el0
	mrs	x9, pmevcntr5_el0
	mrs	x9, pmevcntr6_el0
	mrs	x9, pmevcntr7_el0
	mrs	x9, pmevcntr8_el0
	mrs	x9, pmevcntr9_el0
	mrs	x9, pmevcntr10_el0
	mrs	x9, pmevcntr11_el0
	mrs	x9, pmevcntr12_el0
	mrs	x9, pmevcntr13_el0
	mrs	x9, pmevcntr14_el0
	mrs	x9, pmevcntr15_el0
	mrs	x9, pmevcntr16_el0
	mrs	x9, pmevcntr17_el0
	mrs	x9, pmevcntr18_el0
	mrs	x9, pmevcntr19_el0
	mrs	x9, pmevcntr20_el0
	mrs	x9, pmevcntr21_el0
	mrs	x9, pmevcntr22_el0
	mrs	x9, pmevcntr23_el0
	mrs	x9, pmevcntr24_el0
	mrs	x9, pmevcntr25_el0
	mrs	x9, pmevcntr26_el0
	mrs	x9, pmevcntr27_el0
	mrs	x9, pmevcntr28_el0
	mrs	x9, pmevcntr29_el0
	mrs	x9, pmevcntr30_el0
	mrs	x9, pmevtyper0_el0
	mrs	x9, pmevtyper1_el0
	mrs	x9, pmevtyper2_el0
	mrs	x9, pmevtyper3_el0
	mrs	x9, pmevtyper4_el0
	mrs	x9, pmevtyper5_el0
	mrs	x9, pmevtyper6_el0
	mrs	x9, pmevtyper7_el0
	mrs	x9, pmevtyper8_el0
	mrs	x9, pmevtyper9_el0
	mrs	x9, pmevtyper10_el0
	mrs	x9, pmevtyper11_el0
	mrs	x9, pmevtyper12_el0
	mrs	x9, pmevtyper13_el0
	mrs	x9, pmevtyper14_el0
	mrs	x9, pmevtyper15_el0
	mrs	x9, pmevtyper16_el0
	mrs	x9, pmevtyper17_el0
	mrs	x9, pmevtyper18_el0
	mrs	x9, pmevtyper19_el0
	mrs	x9, pmevtyper20_el0
	mrs	x9, pmevtyper21_el0
	mrs	x9, pmevtyper22_el0
	mrs	x9, pmevtyper23_el0
	mrs	x9, pmevtyper24_el0
	mrs	x9, pmevtyper25_el0
	mrs	x9, pmevtyper26_el0
	mrs	x9, pmevtyper27_el0
	mrs	x9, pmevtyper28_el0
	mrs	x9, pmevtyper29_el0
	mrs	x9, pmevtyper30_el0
	mrs	x9, pmccfiltr_el0
	mrs	x9, cnthctl_el2
	mrs	x9, cnthp_tval_el2
	mrs	x9, cnthp_ctl_el2
	mrs	x9, cnthp_cval_el2
	mrs	x9, cntps_tval_el1
	mrs	x9, cntps_ctl_el1
	mrs	x9, cntps_cval_el1

	msr	oslar_el1, x0
	msr	pmswinc_el0, x0

	nop

	lsr	x0, x1, #0
	lsr	x0, x1, #1
	lsr	x0, x1, #2
	lsr	x0, x1, #3
	lsr	x0, x1, #60
	lsr	x0, x1, #61
	lsr	x0, x1, #62
	lsr	x0, x1, #63

	lsl	x0, x1, #0
	lsl	x0, x1, #1
	lsl	x0, x1, #2
	lsl	x0, x1, #3
	lsl	x0, x1, #60
	lsl	x0, x1, #61
	lsl	x0, x1, #62
	lsl	x0, x1, #63

	bfm	w2, w3, #10, #12
	bfm	x0, x1, #3, #4
	bfi	x1, x2, #3, #4
	bfxil	x1, x2, #3, #4

	subs	x0, xzr, x1, lsl #4
	subs	xzr, x0, x1, lsl #4
	subs	xzr, xzr, x1, lsl #4


	bic	w0, w1, w2, lsl #31
	.word	(0x0a227c20 | (1 << 15))


	add	sp, sp, #0x88, lsl #0
	add	sp, sp, #0x88, lsl #12

	add	x0, x1, x2, lsl #3
	add	x0, x1, x3, lsr #4
	add	x0, x1, xzr, asr #5


	adds	x0, sp, w0, uxtw
	cmn	x0, w0, uxtw

	add	sp, sp, w0, uxtw
	add	x9, sp, w0, lsl #0

	nop

	add	sp, sp, w0, uxtw
	add	sp, sp, w0, uxtw

	hlt	#0
	add	x0, x1, w0, lsl #4

	nop
	add	x9, sp, w0, lsl #0
	add	x9, x9, w0, lsl #0
	add	x9, sp, w0, sxtb #0
	add	x9, x9, w0, sxtb #0
	nop

	add	x0, x1, w0, lsl #4
	add	w0, w1, w2, lsl #4

	add	sp, sp, w0, sxtb #0
	add	sp, sp, w0, sxtb #1
	add	sp, sp, w0, sxtb #4
	add	sp, sp, x0, sxtx #0
	add	sp, sp, x0, sxtx #1
	add	sp, sp, x0, sxtx #4



	nop
	nop
	nop
	nop
