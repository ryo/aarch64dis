/* define code format  { {bitpos, bitwidth}, ... (maximum 8 args) } */
#define FMT_NOARG			\
	{{ 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RN				\
	{{ 5, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RN_RT			\
	{{ 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_CRM				\
	{{ 8, 4}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_CRM_OP2			\
	{{ 8, 4}, { 5, 3}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OP1_CRM_OP2			\
	{{16, 3}, { 8, 4}, { 5, 3}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OP1_CRN_CRM_OP2_RT		\
	{{16, 3}, {12, 4}, { 8, 4}, { 5, 3}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RM_RN_RD			\
	{{16, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RS_RN_RT			\
	{{16, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RM_RA_RN_RD			\
	{{16, 5}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM9_RN_RT			\
	{{12, 9}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_RM_OPT_SHIFT_RN_RT		\
	{{16, 5}, {13, 3}, {12, 1}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM16			\
	{{ 5,16}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM16_LL			\
	{{ 5,16}, { 0, 2}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OP0_OP1_CRN_CRM_OP2_RT	\
	{{19, 2}, {16, 3}, {12, 4}, { 8, 4}, { 5, 3}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_IMM7_RT2_RN_RT		\
	{{15, 7}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM12_RN_RT			\
	{{10,12}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OPC_IMM9_RN_RT		\
	{{22, 1}, {12, 9}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OPC_RM_OPT_SHIFT_RN_RT	\
	{{22, 1}, {16, 5}, {13, 3}, {12, 1}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_OPC_IMM12_RN_RT		\
	{{22, 1}, {10,12}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM19_COND			\
	{{ 5,19}, { 0, 4}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM19_RT			\
	{{ 5,19}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMM26			\
	{{ 0,26}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_RN_RT			\
	{{30, 1}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_RT2_RN_RT		\
	{{30, 1}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_RS_RN_RT		\
	{{30, 1}, {16, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_RS_RT2_RN_RT		\
	{{30, 1}, {16, 5}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_IMM9_RN_RT		\
	{{30, 1}, {12, 9}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_RM_OPT_SHIFT_RN_RT	\
	{{30, 1}, {16, 5}, {13, 3}, {12, 1}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_IMM12_RN_RT		\
	{{30, 1}, {10,12}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_IMM19_RT		\
	{{30, 1}, { 5,19}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_IMMLO_IMMHI_RD		\
	{{29, 2}, { 5,19}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RN_RD			\
	{{31, 1}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_OPC_RN_RD		\
	{{31, 1}, {10, 2}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_RN_RD			\
	{{31, 1}, {16, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_SZ_RN_RD		\
	{{31, 1}, {16, 5}, {10, 2}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_RA_RN_RD		\
	{{31, 1}, {16, 5}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_IMM5_COND_RN_NZCV	\
	{{31, 1}, {16, 5}, {12, 4}, { 5, 5}, { 0, 4}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_COND_RN_NZCV		\
	{{31, 1}, {16, 5}, {12, 4}, { 5, 5}, { 0, 4}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_COND_RN_RD		\
	{{31, 1}, {16, 5}, {12, 4}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_OPT_IMM3_RN_RD	\
	{{31, 1}, {16, 5}, {13, 3}, {10, 3}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_RM_OP_IMM3_RN_RD		\
	{{31, 1}, {16, 5}, {13, 3}, {10, 3}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_IMM7_RT2_RN_RT		\
	{{31, 1}, {15, 7}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_N_RM_IMM6_RN_RD		\
	{{31, 1}, {22, 1}, {16, 5}, {10, 6}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_N_RM_IMMS_RN_RD		\
	{{31, 1}, {22, 1}, {16, 5}, {10, 6}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_HW_IMM16_RD		\
	{{31, 1}, {21, 2}, { 5,16}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_N_IMMR_IMMS_RN_RD	\
	{{31, 1}, {22, 1}, {16, 6}, {10, 6}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_SHIFT_RM_IMM6_RN_RD	\
	{{31, 1}, {22, 2}, {16, 5}, {10, 6}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SF_SHIFT_IMM12_RN_RD	\
	{{31, 1}, {22, 2}, {10,12}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SF_IMM19_RT			\
	{{31, 1}, { 5,19}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_B5_B40_IMM14_RT		\
	{{31, 1}, {19, 5}, { 5,14}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_OPC_L_IMM7_RT2_RN_RT	\
	{{30, 2}, {22, 1}, {15, 7}, {10, 5}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_OPC_IMM9_RN_RT		\
	{{30, 2}, {22, 2}, {12, 9}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}
#define FMT_SIZE_OPC_RM_OPT_S_RN_RT	\
	{{30, 2}, {22, 2}, {16, 5}, {13, 3}, {12, 1}, { 5, 5}, { 0, 5}, { 0, 0}}
#define FMT_SIZE_OPC_IMM12_RN_RT	\
	{{30, 2}, {22, 2}, {10,12}, { 5, 5}, { 0, 5}, { 0, 0}, { 0, 0}, { 0, 0}}

static struct insn_info insn_tables[] = {
 /* mask,      pattern,    opcode format,               opfunc             */
 /* ---------  ----------  ---------------------------  ------------------ */
 { 0xffffffff, 0xd6bf03e0, FMT_NOARG,                   op_drps },
 { 0xffffffff, 0xd69f03e0, FMT_NOARG,                   op_eret },
 { 0xfffffc1f, 0xd63f0000, FMT_RN,                      op_blr },
 { 0xfffffc1f, 0xd61f0000, FMT_RN,                      op_br },
 { 0xfffffc1f, 0xd65f0000, FMT_RN,                      op_ret },
 { 0xfffffc00, 0x08dffc00, FMT_RN_RT,                   op_ldarb },
 { 0xfffffc00, 0x48dffc00, FMT_RN_RT,                   op_ldarh },
 { 0xfffffc00, 0x085ffc00, FMT_RN_RT,                   op_ldaxrb },
 { 0xfffffc00, 0x485ffc00, FMT_RN_RT,                   op_ldaxrh },
 { 0xfffffc00, 0x085f7c00, FMT_RN_RT,                   op_ldxrb },
 { 0xfffffc00, 0x485f7c00, FMT_RN_RT,                   op_ldxrh },
 { 0xfffffc00, 0x089ffc00, FMT_RN_RT,                   op_stlrb },
 { 0xfffffc00, 0x489ffc00, FMT_RN_RT,                   op_stlrh },
 { 0xfffff0ff, 0xd503305f, FMT_CRM,                     op_clrex },
 { 0xfffff0ff, 0xd50330bf, FMT_CRM,                     op_dmb },
 { 0xfffff0ff, 0xd503309f, FMT_CRM,                     op_dsb },
 { 0xfffff0ff, 0xd50330df, FMT_CRM,                     op_isb },
 { 0xfffff01f, 0xd503201f, FMT_CRM_OP2,                 op_hint },
 { 0xfff8f01f, 0xd500401f, FMT_OP1_CRM_OP2,             op_msr_imm },
 { 0xfff80000, 0xd5080000, FMT_OP1_CRN_CRM_OP2_RT,      op_sys },
 { 0xfff80000, 0xd5280000, FMT_OP1_CRN_CRM_OP2_RT,      op_sysl },
 { 0xffe0fc00, 0x9b407c00, FMT_RM_RN_RD,                op_smulh },
 { 0xffe0fc00, 0x0800fc00, FMT_RS_RN_RT,                op_stlxrb },
 { 0xffe0fc00, 0x4800fc00, FMT_RS_RN_RT,                op_stlxrh },
 { 0xffe0fc00, 0x08007c00, FMT_RS_RN_RT,                op_stxrb },
 { 0xffe0fc00, 0x48007c00, FMT_RS_RN_RT,                op_stxrh },
 { 0xffe0fc00, 0x9bc07c00, FMT_RM_RN_RD,                op_umulh },
 { 0xffe08000, 0x9b208000, FMT_RM_RA_RN_RD,             op_smsubl },
 { 0xffe08000, 0x9ba08000, FMT_RM_RA_RN_RD,             op_umsubl },
 { 0xffe08000, 0x9b200000, FMT_RM_RA_RN_RD,             op_smaddl },
 { 0xffe08000, 0x9ba00000, FMT_RM_RA_RN_RD,             op_umaddl },
 { 0xffe00c00, 0x38400400, FMT_IMM9_RN_RT,              op_ldrb_immpostidx },
 { 0xffe00c00, 0x38400c00, FMT_IMM9_RN_RT,              op_ldrb_immpreidx },
 { 0xffe00c00, 0x38600800, FMT_RM_OPT_SHIFT_RN_RT,      op_ldrb_reg },
 { 0xffe00c00, 0x78400400, FMT_IMM9_RN_RT,              op_ldrh_immpostidx },
 { 0xffe00c00, 0x78400c00, FMT_IMM9_RN_RT,              op_ldrh_immpreidx },
 { 0xffe00c00, 0x78600800, FMT_RM_OPT_SHIFT_RN_RT,      op_ldrh_reg },
 { 0xffe00c00, 0xb8800400, FMT_IMM9_RN_RT,              op_ldrsw_immpostidx },
 { 0xffe00c00, 0xb8800c00, FMT_IMM9_RN_RT,              op_ldrsw_immpreidx },
 { 0xffe00c00, 0xb8a00800, FMT_RM_OPT_SHIFT_RN_RT,      op_ldrsw_reg },
 { 0xffe00c00, 0x38400800, FMT_IMM9_RN_RT,              op_ldtrb },
 { 0xffe00c00, 0x78400800, FMT_IMM9_RN_RT,              op_ldtrh },
 { 0xffe00c00, 0xb8800800, FMT_IMM9_RN_RT,              op_ldtrsw },
 { 0xffe00c00, 0x38400000, FMT_IMM9_RN_RT,              op_ldurb },
 { 0xffe00c00, 0x78400000, FMT_IMM9_RN_RT,              op_ldurh },
 { 0xffe00c00, 0xb8800000, FMT_IMM9_RN_RT,              op_ldursw },
 { 0xffe00c00, 0xf8a00800, FMT_RM_OPT_SHIFT_RN_RT,      op_prfm_reg },
 { 0xffe00c00, 0xf8800000, FMT_IMM9_RN_RT,              op_prfum },
 { 0xffe00c00, 0x38000400, FMT_IMM9_RN_RT,              op_strb_immpostidx },
 { 0xffe00c00, 0x38000c00, FMT_IMM9_RN_RT,              op_strb_immpreidx },
 { 0xffe00c00, 0x38200800, FMT_RM_OPT_SHIFT_RN_RT,      op_strb_reg },
 { 0xffe00c00, 0x78000400, FMT_IMM9_RN_RT,              op_strh_immpostidx },
 { 0xffe00c00, 0x78000c00, FMT_IMM9_RN_RT,              op_strh_immpreidx },
 { 0xffe00c00, 0x78200800, FMT_RM_OPT_SHIFT_RN_RT,      op_strh_reg },
 { 0xffe00c00, 0x38000800, FMT_IMM9_RN_RT,              op_sttrb },
 { 0xffe00c00, 0x78000800, FMT_IMM9_RN_RT,              op_sttrh },
 { 0xffe00c00, 0x38000000, FMT_IMM9_RN_RT,              op_sturb },
 { 0xffe00c00, 0x78000000, FMT_IMM9_RN_RT,              op_sturh },
 { 0xffe0001f, 0xd4200000, FMT_IMM16,                   op_brk },
 { 0xffe0001f, 0xd4400000, FMT_IMM16,                   op_hlt },
 { 0xffe0001f, 0xd4000002, FMT_IMM16,                   op_hvc },
 { 0xffe0001f, 0xd4000003, FMT_IMM16,                   op_smc },
 { 0xffe0001f, 0xd4000001, FMT_IMM16,                   op_svc },
 { 0xffe0001c, 0xd4a00000, FMT_IMM16_LL,                op_dcps },
 { 0xffe00000, 0xd5200000, FMT_OP0_OP1_CRN_CRM_OP2_RT,  op_mrs },
 { 0xffe00000, 0xd5000000, FMT_OP0_OP1_CRN_CRM_OP2_RT,  op_msr },
 { 0xffc00000, 0x68c00000, FMT_IMM7_RT2_RN_RT,          op_ldpsw_postidx },
 { 0xffc00000, 0x69c00000, FMT_IMM7_RT2_RN_RT,          op_ldpsw_preidx },
 { 0xffc00000, 0x69400000, FMT_IMM7_RT2_RN_RT,          op_ldpsw_signed },
 { 0xffc00000, 0x39400000, FMT_IMM12_RN_RT,             op_ldrb_immunsign },
 { 0xffc00000, 0x79400000, FMT_IMM12_RN_RT,             op_ldrh_immunsign },
 { 0xffc00000, 0xb9800000, FMT_IMM12_RN_RT,             op_ldrsw_immunsign },
 { 0xffc00000, 0xf9800000, FMT_IMM12_RN_RT,             op_prfm_imm },
 { 0xffc00000, 0x39000000, FMT_IMM12_RN_RT,             op_strb_immunsign },
 { 0xffc00000, 0x79000000, FMT_IMM12_RN_RT,             op_strh_immunsign },
 { 0xffa00c00, 0x38800400, FMT_OPC_IMM9_RN_RT,          op_ldrsb_immpostidx },
 { 0xffa00c00, 0x38800c00, FMT_OPC_IMM9_RN_RT,          op_ldrsb_immpreidx },
 { 0xffa00c00, 0x38a00800, FMT_OPC_RM_OPT_SHIFT_RN_RT,  op_ldrsb_reg },
 { 0xffa00c00, 0x78800400, FMT_OPC_IMM9_RN_RT,          op_ldrsh_immpostidx },
 { 0xffa00c00, 0x78800c00, FMT_OPC_IMM9_RN_RT,          op_ldrsh_immpreidx },
 { 0xffa00c00, 0x78a00800, FMT_OPC_RM_OPT_SHIFT_RN_RT,  op_ldrsh_reg },
 { 0xffa00c00, 0x38800800, FMT_OPC_IMM9_RN_RT,          op_ldtrsb },
 { 0xffa00c00, 0x78800800, FMT_OPC_IMM9_RN_RT,          op_ldtrsh },
 { 0xffa00c00, 0x38800000, FMT_OPC_IMM9_RN_RT,          op_ldursb },
 { 0xffa00c00, 0x78800000, FMT_OPC_IMM9_RN_RT,          op_ldursh },
 { 0xff800000, 0x39800000, FMT_OPC_IMM12_RN_RT,         op_ldrsb_immunsign },
 { 0xff800000, 0x79800000, FMT_OPC_IMM12_RN_RT,         op_ldrsh_immunsign },
 { 0xff000010, 0x54000000, FMT_IMM19_COND,              op_b_cond },
 { 0xff000000, 0x98000000, FMT_IMM19_RT,                op_ldrsw_literal },
 { 0xff000000, 0xd8000000, FMT_IMM19_RT,                op_prfm_literal },
 { 0xfc000000, 0x14000000, FMT_IMM26,                   op_b },
 { 0xfc000000, 0x94000000, FMT_IMM26,                   op_bl },
 { 0xbffffc00, 0x88dffc00, FMT_SIZE_RN_RT,              op_ldar },
 { 0xbffffc00, 0x885ffc00, FMT_SIZE_RN_RT,              op_ldaxr },
 { 0xbffffc00, 0x885f7c00, FMT_SIZE_RN_RT,              op_ldxr },
 { 0xbffffc00, 0x889ffc00, FMT_SIZE_RN_RT,              op_stlr },
 { 0xbfff8000, 0x887f8000, FMT_SIZE_RT2_RN_RT,          op_ldaxp },
 { 0xbfff8000, 0x887f0000, FMT_SIZE_RT2_RN_RT,          op_ldxp },
 { 0xbfe0fc00, 0x8800fc00, FMT_SIZE_RS_RN_RT,           op_stlxr },
 { 0xbfe0fc00, 0x88007c00, FMT_SIZE_RS_RN_RT,           op_stxr },
 { 0xbfe08000, 0x88208000, FMT_SIZE_RS_RT2_RN_RT,       op_stlxp },
 { 0xbfe08000, 0x88200000, FMT_SIZE_RS_RT2_RN_RT,       op_stxp },
 { 0xbfe00c00, 0xb8400400, FMT_SIZE_IMM9_RN_RT,         op_ldr_immpostidx },
 { 0xbfe00c00, 0xb8400c00, FMT_SIZE_IMM9_RN_RT,         op_ldr_immpreidx },
 { 0xbfe00c00, 0xb8600800, FMT_SIZE_RM_OPT_SHIFT_RN_RT, op_ldr_reg },
 { 0xbfe00c00, 0xb8400800, FMT_SIZE_IMM9_RN_RT,         op_ldtr },
 { 0xbfe00c00, 0xb8400000, FMT_SIZE_IMM9_RN_RT,         op_ldur },
 { 0xbfe00c00, 0xb8000400, FMT_SIZE_IMM9_RN_RT,         op_str_immpostidx },
 { 0xbfe00c00, 0xb8000c00, FMT_SIZE_IMM9_RN_RT,         op_str_immpreidx },
 { 0xbfe00c00, 0xb8200800, FMT_SIZE_RM_OPT_SHIFT_RN_RT, op_str_reg },
 { 0xbfe00c00, 0xb8000800, FMT_SIZE_IMM9_RN_RT,         op_sttr },
 { 0xbfe00c00, 0xb8000000, FMT_SIZE_IMM9_RN_RT,         op_stur },
 { 0xbfc00000, 0xb9400000, FMT_SIZE_IMM12_RN_RT,        op_ldr_immunsign },
 { 0xbfc00000, 0xb9000000, FMT_SIZE_IMM12_RN_RT,        op_str_immunsign },
 { 0xbf000000, 0x18000000, FMT_SIZE_IMM19_RT,           op_ldr_literal },
 { 0x9f000000, 0x10000000, FMT_IMMLO_IMMHI_RD,          op_adr },
 { 0x9f000000, 0x90000000, FMT_IMMLO_IMMHI_RD,          op_adrp },
 { 0x7ffffc00, 0x5ac01400, FMT_SF_RN_RD,                op_cls },
 { 0x7ffffc00, 0x5ac01000, FMT_SF_RN_RD,                op_clz },
 { 0x7ffff000, 0x5ac00000, FMT_SF_OPC_RN_RD,            op_rev },
 { 0x7fe0fc00, 0x5a000000, FMT_SF_RM_RN_RD,             op_sbc },
 { 0x7fe0fc00, 0x7a000000, FMT_SF_RM_RN_RD,             op_sbcs },
 { 0x7fe0fc00, 0x1a000000, FMT_SF_RM_RN_RD,             op_adc },
 { 0x7fe0fc00, 0x3a000000, FMT_SF_RM_RN_RD,             op_adcs },
 { 0x7fe0fc00, 0x1ac02800, FMT_SF_RM_RN_RD,             op_asr_reg },
 { 0x7fe0fc00, 0x1ac02000, FMT_SF_RM_RN_RD,             op_lsl_reg },
 { 0x7fe0fc00, 0x1ac02400, FMT_SF_RM_RN_RD,             op_lsr_reg },
 { 0x7fe0fc00, 0x1ac02c00, FMT_SF_RM_RN_RD,             op_ror_reg },
 { 0x7fe0fc00, 0x1ac00c00, FMT_SF_RM_RN_RD,             op_sdiv },
 { 0x7fe0fc00, 0x1ac00800, FMT_SF_RM_RN_RD,             op_udiv },
 { 0x7fe0f000, 0x1ac04000, FMT_SF_RM_SZ_RN_RD,          op_crc32 },
 { 0x7fe0f000, 0x1ac05000, FMT_SF_RM_SZ_RN_RD,          op_crc32c },
 { 0x7fe08000, 0x1b008000, FMT_SF_RM_RA_RN_RD,          op_msub },
 { 0x7fe08000, 0x1b000000, FMT_SF_RM_RA_RN_RD,          op_madd },
 { 0x7fe00c10, 0x3a400800, FMT_SF_IMM5_COND_RN_NZCV,    op_ccmn_imm },
 { 0x7fe00c10, 0x3a400000, FMT_SF_RM_COND_RN_NZCV,      op_ccmn_reg },
 { 0x7fe00c10, 0x7a400800, FMT_SF_IMM5_COND_RN_NZCV,    op_ccmp_imm },
 { 0x7fe00c10, 0x7a400000, FMT_SF_RM_COND_RN_NZCV,      op_ccmp_reg },
 { 0x7fe00c00, 0x5a800000, FMT_SF_RM_COND_RN_RD,        op_csinv },
 { 0x7fe00c00, 0x5a800400, FMT_SF_RM_COND_RN_RD,        op_csneg },
 { 0x7fe00c00, 0x1a800400, FMT_SF_RM_COND_RN_RD,        op_cinc },
 { 0x7fe00c00, 0x1a800000, FMT_SF_RM_COND_RN_RD,        op_csel },
 { 0x7fe00000, 0x6b200000, FMT_SF_RM_OPT_IMM3_RN_RD,    op_subs_extreg },
 { 0x7fe00000, 0x0b200000, FMT_SF_RM_OPT_IMM3_RN_RD,    op_add_extreg },
 { 0x7fe00000, 0x2b200000, FMT_SF_RM_OP_IMM3_RN_RD,     op_adds_extreg },
 { 0x7fe00000, 0x4b200000, FMT_SF_RM_OPT_IMM3_RN_RD,    op_sub_extreg },
 { 0x7fc00000, 0x28400000, FMT_SF_IMM7_RT2_RN_RT,       op_ldnp },
 { 0x7fc00000, 0x28c00000, FMT_SF_IMM7_RT2_RN_RT,       op_ldp_postidx },
 { 0x7fc00000, 0x29c00000, FMT_SF_IMM7_RT2_RN_RT,       op_ldp_preidx },
 { 0x7fc00000, 0x29400000, FMT_SF_IMM7_RT2_RN_RT,       op_ldp_signed },
 { 0x7fc00000, 0x28000000, FMT_SF_IMM7_RT2_RN_RT,       op_stnp },
 { 0x7fc00000, 0x28800000, FMT_SF_IMM7_RT2_RN_RT,       op_stp_postidx },
 { 0x7fc00000, 0x29800000, FMT_SF_IMM7_RT2_RN_RT,       op_stp_preidx },
 { 0x7fc00000, 0x29000000, FMT_SF_IMM7_RT2_RN_RT,       op_stp_signed },
 { 0x7fa00000, 0x13800000, FMT_SF_N_RM_IMM6_RN_RD,      op_ror_imm },
 { 0x7f800000, 0x12800000, FMT_SF_HW_IMM16_RD,          op_movn },
 { 0x7f800000, 0x52800000, FMT_SF_HW_IMM16_RD,          op_movz },
 { 0x7f800000, 0x32000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_orr_imm },
 { 0x7f800000, 0x13000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_sbfm },
 { 0x7f800000, 0x53000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_ubfm },
 { 0x7f800000, 0x12000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_and_imm },
 { 0x7f800000, 0x72000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_ands_imm },
 { 0x7f800000, 0x33000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_bfi },
 { 0x7f800000, 0x52000000, FMT_SF_N_IMMR_IMMS_RN_RD,    op_eor_imm },
 { 0x7f800000, 0x72800000, FMT_SF_HW_IMM16_RD,          op_movk },
 { 0x7f200000, 0x2a200000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_orn },
 { 0x7f200000, 0x2a000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_orr_reg },
 { 0x7f200000, 0x4b000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_sub_shiftreg },
 { 0x7f200000, 0x6b000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_subs_shiftreg },
 { 0x7f200000, 0x0b000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_add_shiftreg },
 { 0x7f200000, 0x2b000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_adds_shiftreg },
 { 0x7f200000, 0x0a000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_and_shiftreg },
 { 0x7f200000, 0x6a000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_ands_shiftreg },
 { 0x7f200000, 0x0a200000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_bic_shiftreg },
 { 0x7f200000, 0x6a200000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_bics_shiftreg },
 { 0x7f200000, 0x4a200000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_eon_shiftreg },
 { 0x7f200000, 0x4a000000, FMT_SF_SHIFT_RM_IMM6_RN_RD,  op_eor_shiftreg },
 { 0x7f000000, 0x71000000, FMT_SF_SHIFT_IMM12_RN_RD,    op_subs_imm },
 { 0x7f000000, 0x11000000, FMT_SF_SHIFT_IMM12_RN_RD,    op_add_imm },
 { 0x7f000000, 0x31000000, FMT_SF_SHIFT_IMM12_RN_RD,    op_adds_imm },
 { 0x7f000000, 0x35000000, FMT_SF_IMM19_RT,             op_cbnz },
 { 0x7f000000, 0x34000000, FMT_SF_IMM19_RT,             op_cbz },
 { 0x7f000000, 0x51000000, FMT_SF_SHIFT_IMM12_RN_RD,    op_sub_imm },
 { 0x7f000000, 0x37000000, FMT_B5_B40_IMM14_RT,         op_tbnz },
 { 0x7f000000, 0x36000000, FMT_B5_B40_IMM14_RT,         op_tbz },
 { 0x3f800000, 0x2c000000, FMT_OPC_L_IMM7_RT2_RN_RT,    op_simd_ldstnp },
 { 0x3f800000, 0x2c800000, FMT_OPC_L_IMM7_RT2_RN_RT, op_simd_ldstp_postidx },
 { 0x3f800000, 0x2d800000, FMT_OPC_L_IMM7_RT2_RN_RT,    op_simd_ldstp_preidx },
 { 0x3f800000, 0x2d000000, FMT_OPC_L_IMM7_RT2_RN_RT,    op_simd_ldstp_signed },
 { 0x3f200c00, 0x3c000400, FMT_SIZE_OPC_IMM9_RN_RT, op_simd_ldstr_immpostidx },
 { 0x3f200c00, 0x3c000c00, FMT_SIZE_OPC_IMM9_RN_RT, op_simd_ldstr_immpreidx },
 { 0x3f200c00, 0x3c200800, FMT_SIZE_OPC_RM_OPT_S_RN_RT, op_simd_ldstr_reg },
 { 0x3f000000, 0x3d000000, FMT_SIZE_OPC_IMM12_RN_RT, op_simd_ldstr_immunsign },
 { 0x00000000, 0x00000000, FMT_NOARG,                   op_undefined }
};

