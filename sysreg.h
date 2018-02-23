#define SYSREG_ENC(op0, op1, CRn, CRm, op2)		\
	(((op0)<<19)|((op1)<<16)|((CRn)<<12)|((CRm)<<8)|((op2)<<5))
#define SYSREG_MASK	SYSREG_ENC(3,7,15,15,7)

struct sysreg_table {
	uint32_t code;
	const char *regname;
};

/* must be sorted by code */
struct sysreg_table sysreg_table[] = {
	/*	         op0 op1 CRn CRm op2 name			*/
	{	SYSREG_ENC(2, 0,  0,  0, 2), "osdtrrx_el1"		},
	{	SYSREG_ENC(2, 0,  0,  0, 4), "dbgbvr0_el1"		},
	{	SYSREG_ENC(2, 0,  0,  0, 5), "dbgbcr0_el1"		},
	{	SYSREG_ENC(2, 0,  0,  0, 6), "dbgwvr0_el1"		},
	{	SYSREG_ENC(2, 0,  0,  0, 7), "dbgwcr0_el1"		},
	{	SYSREG_ENC(2, 0,  0,  1, 4), "dbgbvr1_el1"		},
	{	SYSREG_ENC(2, 0,  0,  1, 5), "dbgbcr1_el1"		},
	{	SYSREG_ENC(2, 0,  0,  1, 6), "dbgwvr1_el1"		},
	{	SYSREG_ENC(2, 0,  0,  1, 7), "dbgwcr1_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 0), "mdccint_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 2), "mdscr_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 4), "dbgbvr2_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 5), "dbgbcr2_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 6), "dbgwvr2_el1"		},
	{	SYSREG_ENC(2, 0,  0,  2, 7), "dbgwcr2_el1"		},
	{	SYSREG_ENC(2, 0,  0,  3, 2), "osdtrtx_el1"		},
	{	SYSREG_ENC(2, 0,  0,  3, 4), "dbgbvr3_el1"		},
	{	SYSREG_ENC(2, 0,  0,  3, 5), "dbgbcr3_el1"		},
	{	SYSREG_ENC(2, 0,  0,  3, 6), "dbgwvr3_el1"		},
	{	SYSREG_ENC(2, 0,  0,  3, 7), "dbgwcr3_el1"		},
	{	SYSREG_ENC(2, 0,  0,  4, 4), "dbgbvr4_el1"		},
	{	SYSREG_ENC(2, 0,  0,  4, 5), "dbgbcr4_el1"		},
	{	SYSREG_ENC(2, 0,  0,  4, 6), "dbgwvr4_el1"		},
	{	SYSREG_ENC(2, 0,  0,  4, 7), "dbgwcr4_el1"		},
	{	SYSREG_ENC(2, 0,  0,  5, 4), "dbgbvr5_el1"		},
	{	SYSREG_ENC(2, 0,  0,  5, 5), "dbgbcr5_el1"		},
	{	SYSREG_ENC(2, 0,  0,  5, 6), "dbgwvr5_el1"		},
	{	SYSREG_ENC(2, 0,  0,  5, 7), "dbgwcr5_el1"		},
	{	SYSREG_ENC(2, 0,  0,  6, 2), "oseccr_el1"		},
	{	SYSREG_ENC(2, 0,  0,  6, 4), "dbgbvr6_el1"		},
	{	SYSREG_ENC(2, 0,  0,  6, 5), "dbgbcr6_el1"		},
	{	SYSREG_ENC(2, 0,  0,  6, 6), "dbgwvr6_el1"		},
	{	SYSREG_ENC(2, 0,  0,  6, 7), "dbgwcr6_el1"		},
	{	SYSREG_ENC(2, 0,  0,  7, 4), "dbgbvr7_el1"		},
	{	SYSREG_ENC(2, 0,  0,  7, 5), "dbgbcr7_el1"		},
	{	SYSREG_ENC(2, 0,  0,  7, 6), "dbgwvr7_el1"		},
	{	SYSREG_ENC(2, 0,  0,  7, 7), "dbgwcr7_el1"		},
	{	SYSREG_ENC(2, 0,  0,  8, 4), "dbgbvr8_el1"		},
	{	SYSREG_ENC(2, 0,  0,  8, 5), "dbgbcr8_el1"		},
	{	SYSREG_ENC(2, 0,  0,  8, 6), "dbgwvr8_el1"		},
	{	SYSREG_ENC(2, 0,  0,  8, 7), "dbgwcr8_el1"		},
	{	SYSREG_ENC(2, 0,  0,  9, 4), "dbgbvr9_el1"		},
	{	SYSREG_ENC(2, 0,  0,  9, 5), "dbgbcr9_el1"		},
	{	SYSREG_ENC(2, 0,  0,  9, 6), "dbgwvr9_el1"		},
	{	SYSREG_ENC(2, 0,  0,  9, 7), "dbgwcr9_el1"		},
	{	SYSREG_ENC(2, 0,  0, 10, 4), "dbgbvr10_el1"		},
	{	SYSREG_ENC(2, 0,  0, 10, 5), "dbgbcr10_el1"		},
	{	SYSREG_ENC(2, 0,  0, 10, 6), "dbgwvr10_el1"		},
	{	SYSREG_ENC(2, 0,  0, 10, 7), "dbgwcr10_el1"		},
	{	SYSREG_ENC(2, 0,  0, 11, 4), "dbgbvr11_el1"		},
	{	SYSREG_ENC(2, 0,  0, 11, 5), "dbgbcr11_el1"		},
	{	SYSREG_ENC(2, 0,  0, 11, 6), "dbgwvr11_el1"		},
	{	SYSREG_ENC(2, 0,  0, 11, 7), "dbgwcr11_el1"		},
	{	SYSREG_ENC(2, 0,  0, 12, 4), "dbgbvr12_el1"		},
	{	SYSREG_ENC(2, 0,  0, 12, 5), "dbgbcr12_el1"		},
	{	SYSREG_ENC(2, 0,  0, 12, 6), "dbgwvr12_el1"		},
	{	SYSREG_ENC(2, 0,  0, 12, 7), "dbgwcr12_el1"		},
	{	SYSREG_ENC(2, 0,  0, 13, 4), "dbgbvr13_el1"		},
	{	SYSREG_ENC(2, 0,  0, 13, 5), "dbgbcr13_el1"		},
	{	SYSREG_ENC(2, 0,  0, 13, 6), "dbgwvr13_el1"		},
	{	SYSREG_ENC(2, 0,  0, 13, 7), "dbgwcr13_el1"		},
	{	SYSREG_ENC(2, 0,  0, 14, 4), "dbgbvr14_el1"		},
	{	SYSREG_ENC(2, 0,  0, 14, 5), "dbgbcr14_el1"		},
	{	SYSREG_ENC(2, 0,  0, 14, 6), "dbgwvr14_el1"		},
	{	SYSREG_ENC(2, 0,  0, 14, 7), "dbgwcr14_el1"		},
	{	SYSREG_ENC(2, 0,  0, 15, 4), "dbgbvr15_el1"		},
	{	SYSREG_ENC(2, 0,  0, 15, 5), "dbgbcr15_el1"		},
	{	SYSREG_ENC(2, 0,  0, 15, 6), "dbgwvr15_el1"		},
	{	SYSREG_ENC(2, 0,  0, 15, 7), "dbgwcr15_el1"		},
	{	SYSREG_ENC(2, 0,  1,  0, 0), "mdrar_el1"		},
	{	SYSREG_ENC(2, 0,  1,  0, 4), "oslar_el1"		},
	{	SYSREG_ENC(2, 0,  1,  1, 4), "oslsr_el1"		},
	{	SYSREG_ENC(2, 0,  1,  3, 4), "osdlr_el1"		},
	{	SYSREG_ENC(2, 0,  1,  4, 4), "dbgprcr_el1"		},
	{	SYSREG_ENC(2, 0,  7,  8, 6), "dbgclaimset_el1"		},
	{	SYSREG_ENC(2, 0,  7,  9, 6), "dbgclaimclr_el1"		},
	{	SYSREG_ENC(2, 0,  7, 14, 6), "dbgauthstatus_el1"	},
	{	SYSREG_ENC(2, 2,  0,  0, 0), "teecr32_el1"		},
	{	SYSREG_ENC(2, 2,  1,  0, 0), "teehbr32_el1"		},
	{	SYSREG_ENC(2, 3,  0,  1, 0), "mdccsr_el0"		},
	{	SYSREG_ENC(2, 3,  0,  4, 0), "dbgdtr_el0"		},
	{	SYSREG_ENC(2, 3,  0,  5, 0), "dbgdtrrx_el0"		},
	{	SYSREG_ENC(2, 4,  0,  7, 0), "dbgvcr32_el2"		},
	{	SYSREG_ENC(3, 0,  0,  0, 0), "midr_el1"			},
	{	SYSREG_ENC(3, 0,  0,  0, 5), "mpidr_el1"		},
	{	SYSREG_ENC(3, 0,  0,  0, 6), "revidr_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 0), "id_pfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 1), "id_pfr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 2), "id_dfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 3), "id_afr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 4), "id_mmfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 5), "id_mmfr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 6), "id_mmfr2_el1"		},
	{	SYSREG_ENC(3, 0,  0,  1, 7), "id_mmfr3_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 0), "id_isar0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 1), "id_isar1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 2), "id_isar2_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 3), "id_isar3_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 4), "id_isar4_el1"		},
	{	SYSREG_ENC(3, 0,  0,  2, 5), "id_isar5_el1"		},
	{	SYSREG_ENC(3, 0,  0,  3, 0), "mvfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  3, 1), "mvfr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  3, 2), "mvfr2_el1"		},
	{	SYSREG_ENC(3, 0,  0,  4, 0), "id_aa64pfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  4, 1), "id_aa64pfr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  5, 0), "id_aa64dfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  5, 1), "id_aa64dfr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  5, 4), "id_aa64afr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  5, 5), "id_aa64afr1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  6, 0), "id_aa64isar0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  6, 1), "id_aa64isar1_el1"		},
	{	SYSREG_ENC(3, 0,  0,  7, 0), "id_aa64mmfr0_el1"		},
	{	SYSREG_ENC(3, 0,  0,  7, 1), "id_aa64mmfr1_el1"		},
	{	SYSREG_ENC(3, 0,  1,  0, 0), "sctlr_el1"		},
	{	SYSREG_ENC(3, 0,  1,  0, 1), "actlr_el1"		},
	{	SYSREG_ENC(3, 0,  1,  0, 2), "cpacr_el1"		},
	{	SYSREG_ENC(3, 0,  2,  0, 0), "ttbr0_el1"		},
	{	SYSREG_ENC(3, 0,  2,  0, 1), "ttbr1_el1"		},
	{	SYSREG_ENC(3, 0,  2,  0, 2), "tcr_el1"			},
	{	SYSREG_ENC(3, 0,  4,  0, 0), "spsr_el1"			},
	{	SYSREG_ENC(3, 0,  4,  0, 1), "elr_el1"			},
	{	SYSREG_ENC(3, 0,  4,  1, 0), "sp_el0"			},
	{	SYSREG_ENC(3, 0,  4,  2, 0), "spsel"			},
	{	SYSREG_ENC(3, 0,  4,  2, 2), "currentel"		},
	{	SYSREG_ENC(3, 0,  5,  1, 0), "afsr0_el1"		},
	{	SYSREG_ENC(3, 0,  5,  1, 1), "afsr1_el1"		},
	{	SYSREG_ENC(3, 0,  5,  2, 0), "esr_el1"			},
	{	SYSREG_ENC(3, 0,  6,  0, 0), "far_el1"			},
	{	SYSREG_ENC(3, 0,  7,  4, 0), "par_el1"			},
	{	SYSREG_ENC(3, 0,  9, 14, 1), "pmintenset_el1"		},
	{	SYSREG_ENC(3, 0,  9, 14, 2), "pmintenclr_el1"		},
	{	SYSREG_ENC(3, 0, 10,  2, 0), "mair_el1"			},
	{	SYSREG_ENC(3, 0, 10,  3, 0), "amair_el1"		},
	{	SYSREG_ENC(3, 0, 12,  0, 0), "vbar_el1"			},
	{	SYSREG_ENC(3, 0, 12,  0, 1), "rvbar_el1"		},
	{	SYSREG_ENC(3, 0, 12,  0, 2), "rmr_el1"			},
	{	SYSREG_ENC(3, 0, 12,  1, 0), "isr_el1"			},
	{	SYSREG_ENC(3, 0, 13,  0, 1), "contextidr_el1"		},
	{	SYSREG_ENC(3, 0, 13,  0, 4), "tpidr_el1"		},
	{	SYSREG_ENC(3, 0, 14,  1, 0), "cntkctl_el1"		},
	{	SYSREG_ENC(3, 1,  0,  0, 0), "ccsidr_el1"		},
	{	SYSREG_ENC(3, 1,  0,  0, 1), "clidr_el1"		},
	{	SYSREG_ENC(3, 1,  0,  0, 7), "aidr_el1"			},
	{	SYSREG_ENC(3, 2,  0,  0, 0), "csselr_el1"		},
	{	SYSREG_ENC(3, 3,  0,  0, 1), "ctr_el0"			},
	{	SYSREG_ENC(3, 3,  0,  0, 7), "dczid_el0"		},
	{	SYSREG_ENC(3, 3,  4,  2, 0), "nzcv"			},
	{	SYSREG_ENC(3, 3,  4,  2, 1), "daif"			},
	{	SYSREG_ENC(3, 3,  4,  4, 0), "fpcr"			},
	{	SYSREG_ENC(3, 3,  4,  4, 1), "fpsr"			},
	{	SYSREG_ENC(3, 3,  4,  5, 0), "dspsr_el0"		},
	{	SYSREG_ENC(3, 3,  4,  5, 1), "dlr_el0"			},
	{	SYSREG_ENC(3, 3,  9, 12, 0), "pmcr_el0"			},
	{	SYSREG_ENC(3, 3,  9, 12, 1), "pmcntenset_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 2), "pmcntenclr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 3), "pmovsclr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 4), "pmswinc_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 5), "pmselr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 6), "pmceid0_el0"		},
	{	SYSREG_ENC(3, 3,  9, 12, 7), "pmceid1_el0"		},
	{	SYSREG_ENC(3, 3,  9, 13, 0), "pmccntr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 13, 1), "pmxevtyper_el0"		},
	{	SYSREG_ENC(3, 3,  9, 13, 2), "pmxevcntr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 14, 0), "pmuserenr_el0"		},
	{	SYSREG_ENC(3, 3,  9, 14, 3), "pmovsset_el0"		},
	{	SYSREG_ENC(3, 3, 13,  0, 2), "tpidr_el0"		},
	{	SYSREG_ENC(3, 3, 13,  0, 3), "tpidrro_el0"		},
	{	SYSREG_ENC(3, 3, 14,  0, 0), "cntfrq_el0"		},
	{	SYSREG_ENC(3, 3, 14,  0, 1), "cntpct_el0"		},
	{	SYSREG_ENC(3, 3, 14,  0, 2), "cntvct_el0"		},
	{	SYSREG_ENC(3, 3, 14,  2, 0), "cntp_tval_el0"		},
	{	SYSREG_ENC(3, 3, 14,  2, 1), "cntp_ctl_el0"		},
	{	SYSREG_ENC(3, 3, 14,  2, 2), "cntp_cval_el0"		},
	{	SYSREG_ENC(3, 3, 14,  3, 0), "cntv_tval_el0"		},
	{	SYSREG_ENC(3, 3, 14,  3, 1), "cntv_ctl_el0"		},
	{	SYSREG_ENC(3, 3, 14,  3, 2), "cntv_cval_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 0), "pmevcntr0_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 1), "pmevcntr1_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 2), "pmevcntr2_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 3), "pmevcntr3_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 4), "pmevcntr4_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 5), "pmevcntr5_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 6), "pmevcntr6_el0"		},
	{	SYSREG_ENC(3, 3, 14,  8, 7), "pmevcntr7_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 0), "pmevcntr8_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 1), "pmevcntr9_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 2), "pmevcntr10_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 3), "pmevcntr11_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 4), "pmevcntr12_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 5), "pmevcntr13_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 6), "pmevcntr14_el0"		},
	{	SYSREG_ENC(3, 3, 14,  9, 7), "pmevcntr15_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 0), "pmevcntr16_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 1), "pmevcntr17_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 2), "pmevcntr18_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 3), "pmevcntr19_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 4), "pmevcntr20_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 5), "pmevcntr21_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 6), "pmevcntr22_el0"		},
	{	SYSREG_ENC(3, 3, 14, 10, 7), "pmevcntr23_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 0), "pmevcntr24_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 1), "pmevcntr25_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 2), "pmevcntr26_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 3), "pmevcntr27_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 4), "pmevcntr28_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 5), "pmevcntr29_el0"		},
	{	SYSREG_ENC(3, 3, 14, 11, 6), "pmevcntr30_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 0), "pmevtyper0_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 1), "pmevtyper1_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 2), "pmevtyper2_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 3), "pmevtyper3_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 4), "pmevtyper4_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 5), "pmevtyper5_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 6), "pmevtyper6_el0"		},
	{	SYSREG_ENC(3, 3, 14, 12, 7), "pmevtyper7_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 0), "pmevtyper8_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 1), "pmevtyper9_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 2), "pmevtyper10_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 3), "pmevtyper11_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 4), "pmevtyper12_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 5), "pmevtyper13_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 6), "pmevtyper14_el0"		},
	{	SYSREG_ENC(3, 3, 14, 13, 7), "pmevtyper15_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 0), "pmevtyper16_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 1), "pmevtyper17_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 2), "pmevtyper18_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 3), "pmevtyper19_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 4), "pmevtyper20_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 5), "pmevtyper21_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 6), "pmevtyper22_el0"		},
	{	SYSREG_ENC(3, 3, 14, 14, 7), "pmevtyper23_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 0), "pmevtyper24_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 1), "pmevtyper25_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 2), "pmevtyper26_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 3), "pmevtyper27_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 4), "pmevtyper28_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 5), "pmevtyper29_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 6), "pmevtyper30_el0"		},
	{	SYSREG_ENC(3, 3, 14, 15, 7), "pmccfiltr_el0"		},
	{	SYSREG_ENC(3, 4,  0,  0, 0), "vpidr_el2"		},
	{	SYSREG_ENC(3, 4,  0,  0, 5), "vmpidr_el2"		},
	{	SYSREG_ENC(3, 4,  1,  0, 0), "sctlr_el2"		},
	{	SYSREG_ENC(3, 4,  1,  0, 1), "actlr_el2"		},
	{	SYSREG_ENC(3, 4,  1,  1, 0), "hcr_el2"			},
	{	SYSREG_ENC(3, 4,  1,  1, 1), "mdcr_el2"			},
	{	SYSREG_ENC(3, 4,  1,  1, 2), "cptr_el2"			},
	{	SYSREG_ENC(3, 4,  1,  1, 3), "hstr_el2"			},
	{	SYSREG_ENC(3, 4,  1,  1, 7), "hacr_el2"			},
	{	SYSREG_ENC(3, 4,  2,  0, 0), "ttbr0_el2"		},
	{	SYSREG_ENC(3, 4,  2,  0, 2), "tcr_el2"			},
	{	SYSREG_ENC(3, 4,  2,  1, 0), "vttbr_el2"		},
	{	SYSREG_ENC(3, 4,  2,  1, 2), "vtcr_el2"			},
	{	SYSREG_ENC(3, 4,  3,  0, 0), "dacr32_el2"		},
	{	SYSREG_ENC(3, 4,  4,  0, 0), "spsr_el2"			},
	{	SYSREG_ENC(3, 4,  4,  0, 1), "elr_el2"			},
	{	SYSREG_ENC(3, 4,  4,  1, 0), "sp_el1"			},
	{	SYSREG_ENC(3, 4,  4,  3, 0), "spsr_irq"			},
	{	SYSREG_ENC(3, 4,  4,  3, 1), "spsr_abt"			},
	{	SYSREG_ENC(3, 4,  4,  3, 2), "spsr_und"			},
	{	SYSREG_ENC(3, 4,  4,  3, 3), "spsr_fiq"			},
	{	SYSREG_ENC(3, 4,  5,  0, 1), "ifsr32_el2"		},
	{	SYSREG_ENC(3, 4,  5,  1, 0), "afsr0_el2"		},
	{	SYSREG_ENC(3, 4,  5,  1, 1), "afsr1_el2"		},
	{	SYSREG_ENC(3, 4,  5,  2, 0), "esr_el2"			},
	{	SYSREG_ENC(3, 4,  5,  3, 0), "fpexc32_el2"		},
	{	SYSREG_ENC(3, 4,  6,  0, 0), "far_el2"			},
	{	SYSREG_ENC(3, 4,  6,  0, 4), "hpfar_el2"		},
	{	SYSREG_ENC(3, 4, 10,  2, 0), "mair_el2"			},
	{	SYSREG_ENC(3, 4, 10,  3, 0), "amair_el2"		},
	{	SYSREG_ENC(3, 4, 12,  0, 0), "vbar_el2"			},
	{	SYSREG_ENC(3, 4, 12,  0, 1), "rvbar_el2"		},
	{	SYSREG_ENC(3, 4, 12,  0, 2), "rmr_el2"			},
	{	SYSREG_ENC(3, 4, 13,  0, 2), "tpidr_el2"		},
	{	SYSREG_ENC(3, 4, 14,  0, 3), "cntvoff_el2"		},
	{	SYSREG_ENC(3, 4, 14,  1, 0), "cnthctl_el2"		},
	{	SYSREG_ENC(3, 4, 14,  2, 0), "cnthp_tval_el2"		},
	{	SYSREG_ENC(3, 4, 14,  2, 1), "cnthp_ctl_el2"		},
	{	SYSREG_ENC(3, 4, 14,  2, 2), "cnthp_cval_el2"		},
	{	SYSREG_ENC(3, 6,  1,  0, 0), "sctlr_el3"		},
	{	SYSREG_ENC(3, 6,  1,  0, 1), "actlr_el3"		},
	{	SYSREG_ENC(3, 6,  1,  1, 0), "scr_el3"			},
	{	SYSREG_ENC(3, 6,  1,  1, 1), "sder32_el3"		},
	{	SYSREG_ENC(3, 6,  1,  1, 2), "cptr_el3"			},
	{	SYSREG_ENC(3, 6,  1,  3, 1), "mdcr_el3"			},
	{	SYSREG_ENC(3, 6,  2,  0, 0), "ttbr0_el3"		},
	{	SYSREG_ENC(3, 6,  2,  0, 2), "tcr_el3"			},
	{	SYSREG_ENC(3, 6,  4,  0, 0), "spsr_el3"			},
	{	SYSREG_ENC(3, 6,  4,  0, 1), "elr_el3"			},
	{	SYSREG_ENC(3, 6,  4,  1, 0), "sp_el2"			},
	{	SYSREG_ENC(3, 6,  5,  1, 0), "afsr0_el3"		},
	{	SYSREG_ENC(3, 6,  5,  1, 1), "afsr1_el3"		},
	{	SYSREG_ENC(3, 6,  5,  2, 0), "esr_el3"			},
	{	SYSREG_ENC(3, 6,  6,  0, 0), "far_el3"			},
	{	SYSREG_ENC(3, 6, 10,  2, 0), "mair_el3"			},
	{	SYSREG_ENC(3, 6, 10,  3, 0), "amair_el3"		},
	{	SYSREG_ENC(3, 6, 12,  0, 0), "vbar_el3"			},
	{	SYSREG_ENC(3, 6, 12,  0, 1), "rvbar_el3"		},
	{	SYSREG_ENC(3, 6, 12,  0, 2), "rmr_el3"			},
	{	SYSREG_ENC(3, 6, 13,  0, 2), "tpidr_el3"		},
	{	SYSREG_ENC(3, 7, 14,  2, 0), "cntps_tval_el1"		},
	{	SYSREG_ENC(3, 7, 14,  2, 1), "cntps_ctl_el1"		},
	{	SYSREG_ENC(3, 7, 14,  2, 2), "cntps_cval_el1"		}
};
