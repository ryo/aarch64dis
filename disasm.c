/*
 * Copyright (c) 2018 Ryo Shimizu <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/bitops.h>

#include "disasm.h"

struct aarch64_insn_info;

static int test_printf(char const *fmt, ...);
#define PRINTF	test_printf


#define OPFUNC_DECL(func,a,b,c,d,e,f)		\
func(uint64_t pc, uint32_t insn,		\
     uint64_t a, uint64_t b, uint64_t c,	\
     uint64_t d, uint64_t e, uint64_t f)

struct bitinfo {
	uint8_t pos;
	uint8_t width;
};

struct aarch64_insn_info {
	uint32_t mask;
	uint32_t code;
#define INSN_MAXARG	6
	struct bitinfo bitinfo[INSN_MAXARG];
	OPFUNC_DECL(void (*opfunc),,,,,,);
};

#define UNUSED1	arg1 __unused
#define UNUSED2	arg2 __unused
#define UNUSED3	arg3 __unused
#define UNUSED4	arg4 __unused
#define UNUSED5	arg5 __unused
#define UNUSED6	arg6 __unused

static const char *z_wregs[32] = {
	 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",  "w9",
	"w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
	"w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29",
	"w30", "wzr"
};
static const char *z_xregs[32] = {
	 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
	"x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
	"x30", "xzr"
};
static const char *s_wregs[32] = {
	 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",  "w8",  "w9",
	"w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
	"w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29",
	"w30", "wsp"
};
static const char *s_xregs[32] = {
	 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
	"x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
	"x30", "sp"
};
#define ZREGNAME(s, n)	((s == 0) ? z_wregs[(n) & 31] : z_xregs[(n) & 31])
#define SREGNAME(s, n)	((s == 0) ? s_wregs[(n) & 31] : s_xregs[(n) & 31])

static const char *cregs[16] = {
	 "C0",  "C1",  "C2",  "C3",  "C4",  "C5",  "C6",  "C7",
	 "C8",  "C9", "C10", "C11", "C12", "C13", "C14", "C15",
};
#define CREGNAME(n)	cregs[(n) & 15]

static const char *conditioncode[16] = {
	"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc", 
	"hi", "ls", "ge", "lt", 
	"gt", "le", "al", "nv"
};
#define COND(c)	conditioncode[(c) & 15]
#define IVCOND(c)	conditioncode[((c) ^ 1) & 15]

static const char *barrierop[16] = {
	 "#0", "oshld", "oshst", "osh",
	 "#4", "nshld", "nshst", "nsh",
	 "#8", "ishld", "ishst", "ish",
	"#12",    "ld",    "st",  "sy"
};
#define BARRIER(op)	barrierop[(op) & 15]

static const char *prefetchop[32] = {
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
	"pldl3keep", "pldl3strm",        "#6",        "#7",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm",
	"plil3keep", "plil3strm",       "#14",       "#15",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
	"pstl3keep", "pstl3strm",       "#22",       "#23",
	      "#24",       "#25",       "#26",       "#27",
	      "#28",       "#29",       "#30",       "#31"
};
#define PREFETCH(op)	prefetchop[(op) & 31]

static int64_t
SignExtend(int bitwidth, uint64_t imm, unsigned int multiply)
{
	const uint64_t signbit = (1 << (bitwidth - 1));
	const uint64_t immmax = signbit << 1;

	if (imm & signbit)
		imm -= immmax;
	return imm * multiply;
}

static uint64_t
ZeroExtend(int bitwidth, uint64_t imm, unsigned int multiply)
{
	return imm * multiply;
}

/* rotate right. if n < 0, rotate left. */
static uint64_t
rotate(int bitwidth, uint64_t v, int n)
{
	n &= (bitwidth - 1);
	return (((v << (bitwidth - n)) | (v >> n)) & ((1UL << bitwidth) - 1));
}

static bool
MoveWidePreferred(uint64_t sf, uint64_t n, uint64_t immr, uint64_t imms)
{
	const int width = (sf == 0) ? 32 : 64;

	if ((sf != 0) && (n == 0))
		return false;
	if ((sf == 0) && ((n != 0) || (immr > 0x1f)))
		return false;
	if (imms < 16) {
		return ((-immr & 15) <= (15 - imms));
	}
	if (imms >= (uint64_t)(width - 15)) {
		return ((immr & 15) <= (imms - (width - 15)));
	}
	return false;
}

static bool
ValidBitMasks(uint64_t sf, uint64_t n, uint64_t immr, uint64_t imms)
{
	int esize, len;

	if ((sf == 0) && (n != 0))
		return false;

	len = fls64((n << 6) + (~imms & 0x3f)) - 1;
	if (len < 0)
		return false;

	esize = (1 << len);
	imms &= (esize - 1);
	if (imms == (uint64_t)(esize - 1))
		return false;

	return true;
}

static uint64_t
DecodeBitMasks(uint64_t sf, uint64_t n, uint64_t immr, uint64_t imms)
{
	const int bitwidth = (sf == 0) ? 32 : 64;
	uint64_t result;
	int esize, len;

	len = fls64((n << 6) + (~imms & 0x3f)) - 1;

	esize = (1 << len);
	imms &= (esize - 1);
	immr &= (esize - 1);

	result = rotate(bitwidth, (1ULL << (imms + 1)) - 1, immr);
	while (esize < bitwidth) {
		result |= (result >> esize);
		esize <<= 1;
	}
	return (result & ((1UL << bitwidth) - 1));
}

static bool
BFXPreferred(uint64_t sf, uint64_t opc, uint64_t imms, uint64_t immr)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	if (imms < immr)
		return false;

	if (imms == (bitwidth - 1))
		return false;

	if (immr == 0) {
		if ((sf == 0) && ((imms == 7) || (imms == 15)))
			return false;
		if ((sf != 0) && (opc == 0) &&
		    ((imms == 7) || (imms == 15) || (imms == 31)))
			return false;
	}

	return true;
}

#define SHIFTOP2(s, op1, op2)		((const char *[]){ op1, op2 })[(s)]
#define SHIFTOP4(s, op1, op2, op3, op4)	((const char *[]){ op1, op2, op3, op4 })[(s)]

#if 1
#define UNDEFINED(pc, insn, comment)	\
	PRINTF("%12lx:\t%08x	.word	0x%08x	# \e[31m%s\e[m\n", pc, insn, insn, comment);
#else
#define UNDEFINED(pc, insn, comment)	\
	PRINTF("%12lx:\t%08x	.word	0x%08x\n", pc, insn, insn);
#endif


static void
OPFUNC_DECL(op_undefined, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	UNDEFINED(pc, insn, "undefined");
}

static void
OPFUNC_DECL(op_adc, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	adc	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_adcs, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	adcs	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_add_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_add_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	/* ALIAS: mov_tofrom_sp */
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	if ((Rd == 31 || Rn == 31) && (imm12 == 0)) {
		PRINTF("%12lx:\t%08x	mov	%s, %s\n", pc, insn,
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn));
	} else {
		PRINTF("%12lx:\t%08x	add	%s, %s, #0x%lx%s\n", pc, insn,
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	}
}

static void
OPFUNC_DECL(op_add_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_adds_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: cmn_extreg */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_adds_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	/* ALIAS: cmn_imm */
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	if (Rd == 31) {
		PRINTF("%12lx:\t%08x	cmn	%s, #0x%lx%s\n", pc, insn,
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	} else {
		PRINTF("%12lx:\t%08x	adds	%s, %s, #0x%lx%s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	}
}

static void
OPFUNC_DECL(op_adds_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: cmn_shiftreg */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_adr, immlo, immhi, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("%12lx:\t%08x	adr	%s, %lx\n", pc, insn,
	    ZREGNAME(1, Rd),
	    SignExtend(21, imm, 1) + pc);
}

static void
OPFUNC_DECL(op_adrp, immlo, immhi, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("%12lx:\t%08x	adrp	%s, %lx\n", pc, insn,
	    ZREGNAME(1, Rd),
	    SignExtend(21, imm, 4096) + (pc & -4096));
}

static void
OPFUNC_DECL(op_and_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, immr, imms)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("%12lx:\t%08x	and	%s, %s, #0x%lx\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, immr, imms));
}

static void
OPFUNC_DECL(op_and_shiftreg, sf, shift, Rm, imms, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ands_imm, sf, n, immr, imms, Rn, Rd)
{
	/* ALIAS: tst_imm */

	if (!ValidBitMasks(sf, n, immr, imms)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	if (Rd == 31) {
		PRINTF("%12lx:\t%08x	tst	%s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, immr, imms));
	} else {
		PRINTF("%12lx:\t%08x	ands	%s, %s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, immr, imms));
	}
}

static void
OPFUNC_DECL(op_ands_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: tst_shiftreg */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_asr_imm, sf, n, immr, imms, Rn, Rd)
{
	/* ALIAS: sbfiz,sbfm,sbfx,sxtb,sxth,sxtw */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_asr_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: asrv */

	/* "asr" always the preferred disassembly */
	PRINTF("%12lx:\t%08x	asr	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_at, op1, CRn, CRm, op2, Rt, UNUSED5)
{
	/* ALIAS: dc,ic,sys,tlbi */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_b, imm26, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	b	%lx\n", pc, insn,
	    SignExtend(26, imm26, 4) + pc);
}

static void
OPFUNC_DECL(op_b_cond, imm19, cond, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	b.%s	%lx\n", pc, insn,
	    COND(cond),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_bfi, sf, n, immr, imms, Rn, Rd)
{
	/* ALIAS: bfm,bfxil */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_bic_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_bics_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_bl, imm26, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	bl	%lx\n", pc, insn,
	    SignExtend(26, imm26, 4) + pc);
}

static void
OPFUNC_DECL(op_blr, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	blr	%s\n", pc, insn,
	    ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_br, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	br	%s\n", pc, insn,
	    ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_brk, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	brk	#0x%lx\n", pc, insn,
	    imm16);
}

static void
OPFUNC_DECL(op_cbnz, sf, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	cbnz	%s, %lx\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_cbz, sf, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	cbz	%s, %lx\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_ccmn_imm, sf, imm5, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ccmn	%s, #0x%lx, #0x%lx, %s\n", pc, insn,
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    COND(cond));
}

static void
OPFUNC_DECL(op_ccmn_reg, sf, Rm, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ccmn	%s, %s, #0x%lx, %s\n", pc, insn,
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    COND(cond));
}

static void
OPFUNC_DECL(op_ccmp_imm, sf, imm5, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ccmp	%s, #0x%lx, #0x%lx, %s\n", pc, insn,
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    COND(cond));
}

static void
OPFUNC_DECL(op_ccmp_reg, sf, Rm, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ccmp	%s, %s, #0x%lx, %s\n", pc, insn,
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    COND(cond));
}

static void
OPFUNC_DECL(op_cinc, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: cset,csinc */
	if ((Rn == Rm) && (Rn != 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%12lx:\t%08x	cinc	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCOND(cond));
	} else if ((Rn == Rm) && (Rn == 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%12lx:\t%08x	cset	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    IVCOND(cond));
	} else {
		PRINTF("%12lx:\t%08x	csinc	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    COND(cond));
	}
}

static void
OPFUNC_DECL(op_cinv, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: csetm,csinv */
	if ((Rn == Rm) && (Rn != 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%12lx:\t%08x	cinv	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCOND(cond));
	} else if ((Rn == Rm) && (Rn == 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%12lx:\t%08x	csetm	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    IVCOND(cond));
	} else {
		PRINTF("%12lx:\t%08x	csinv	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    COND(cond));
	}
}

static void
OPFUNC_DECL(op_clrex, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (CRm == 15) {
		PRINTF("%12lx:\t%08x	clrex\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	clrex	#d\n", pc, insn, CRm);
	}
}

static void
OPFUNC_DECL(op_cls, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	cls	%s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_clz, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	clz	%s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_cmp_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: subs_extreg */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_cmp_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	/* ALIAS: subs_imm */
	if (Rd == 31) {
		PRINTF("%12lx:\t%08x	cmp	%s, #0x%lx%s\n", pc, insn,
		    SREGNAME(sf, Rn),
		    SignExtend(12, imm12, 1),
		    SHIFTOP2(shift, "", ", lsl #12"));
	} else {
		PRINTF("%12lx:\t%08x	subs	%s, %s, #0x%lx%s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    SignExtend(12, imm12, 1),
		    SHIFTOP2(shift, "", ", lsl #12"));
	}
}

static void
OPFUNC_DECL(op_cmp_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: negs,subs_shiftreg */
	if (Rd == 31) {
		if (imm6 == 0) {
			PRINTF("%12lx:\t%08x	cmp	%s, %s\n", pc, insn,
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	cmp	%s, %s, %s #%lu\n", pc, insn,
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, "lsl", "lsr", "asr", ""),
			    imm6);
		}
	} else if (Rn == 31) {
		if (imm6 == 0) {
			PRINTF("%12lx:\t%08x	negs	%s, %s\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	negs	%s, %s, %s #%lu\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, "lsl", "lsr", "asr", ""),
			    imm6);
		}
	} else {
		if (imm6 == 0) {
			PRINTF("%12lx:\t%08x	subs	%s, %s, %s\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	subs	%s, %s, %s, %s #%lu\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, "lsl", "lsr", "asr", ""),
			    imm6);
		}
	}
}

static void
OPFUNC_DECL(op_cneg, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: csneg */
	if ((Rn == Rm) && ((cond & 0xe) != 0x0e)) {
		PRINTF("%12lx:\t%08x	cneg	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCOND(cond));
	} else {
		PRINTF("%12lx:\t%08x	csneg	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    COND(cond));
	}
}

static void
OPFUNC_DECL(op_crc32b, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32cb, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32ch, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32cw, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32cx, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32h, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32w, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_crc32x, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_csel, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	PRINTF("%12lx:\t%08x	csel	%s, %s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    COND(cond));
}

static void
OPFUNC_DECL(op_dcps1, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0) {
		PRINTF("%12lx:\t%08x	dpcs1\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	dpcs1	#0x%lx\n", pc, insn,
		    imm16);
	}
}

static void
OPFUNC_DECL(op_dcps2, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0) {
		PRINTF("%12lx:\t%08x	dpcs2\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	dpcs2	#0x%lx\n", pc, insn,
		    imm16);
	}
}

static void
OPFUNC_DECL(op_dcps3, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0) {
		PRINTF("%12lx:\t%08x	dpcs3\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	dpcs3	#0x%lx\n", pc, insn,
		    imm16);
	}
}

static void
OPFUNC_DECL(op_dmb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	dmb	%s\n", pc, insn, BARRIER(CRm));
}

static void
OPFUNC_DECL(op_drps, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	drps\n", pc, insn);
}

static void
OPFUNC_DECL(op_dsb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	dsb	%s\n", pc, insn, BARRIER(CRm));
}

static void
OPFUNC_DECL(op_eon_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_eor_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, immr, imms)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("%12lx:\t%08x	eor	%s, %s, #0x%lx\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, immr, imms));
}

static void
OPFUNC_DECL(op_eor_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_eret, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	eret\n", pc, insn, insn);
}

static void
OPFUNC_DECL(op_extr, sf, n, Rm, imms, Rn, Rd)
{
	if (((sf ^ n) != 0) || (n == 0 && imms >= 0x20)) {
		UNDEFINED(pc, insn, "illegal sf and N");
		return;
	}

	/* ALIAS: ror_imm */
	if (Rn == Rm) {
		PRINTF("%12lx:\t%08x	ror	%s, %s, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    imms);
	} else {
		PRINTF("%12lx:\t%08x	extr	%s, %s, %s, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    imms);
	}
}

static void
OPFUNC_DECL(op_hint, CRm, op2, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	const uint64_t op = CRm << 3 | op2;

	/* ALIAS: nop,sev,sevl,wfe,wfi,yield */
	switch (op) {
	case 0:
	default:
		PRINTF("%12lx:\t%08x	nop\n", pc, insn);
		break;
	case 1:
		PRINTF("%12lx:\t%08x	yield\n", pc, insn);
		break;
	case 2:
		PRINTF("%12lx:\t%08x	wfe\n", pc, insn);
		break;
	case 3:
		PRINTF("%12lx:\t%08x	wfi\n", pc, insn);
		break;
	case 4:
		PRINTF("%12lx:\t%08x	sev\n", pc, insn);
		break;
	case 5:
		PRINTF("%12lx:\t%08x	sevl\n", pc, insn);
		break;
	}
}

static void
OPFUNC_DECL(op_hlt, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	hlt	#0x%lx\n", pc, insn,
	    imm16);
}

static void
OPFUNC_DECL(op_hvc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	hvc	#0x%lx\n", pc, insn,
	    imm16);
}

static void
OPFUNC_DECL(op_isb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (CRm == 15) {
		PRINTF("%12lx:\t%08x	isb\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	isb	#d\n", pc, insn, CRm);
	}
}

static void
OPFUNC_DECL(op_ldar, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldarb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldarh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldaxb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldaxh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldaxp, size, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldaxr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldnp, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("%12lx:\t%08x	ldnp	%s, %s, [%s]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldnp	%s, %s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldp_postidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldp	%s, %s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_ldp_preidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldp	%s, %s, [%s,#%ld]!\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_ldp_signed, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("%12lx:\t%08x	ldp	%s, %s, [%s]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldp	%s, %s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldpsw_postidx, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldpsw_preidx, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldpsw_signed, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldr_immpostidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldr	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldr_immpreidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldr	%s, [%s,#%ld]!\n", pc, insn,
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldr_immunsign, size, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldr	%s, [%s]\n", pc, insn,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldr	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldr_literal, size, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldr	%s, %lx\n", pc, insn,
	    ZREGNAME(size, Rt),
	    SignExtend(19, imm19, 4) + pc);

}

static void
OPFUNC_DECL(op_ldr_reg, size, Rm, option, shift, Rn, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrb_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldrb	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrb_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrb_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldrb	%s, [%s]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldrb	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_ldrb_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrh_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldrh	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrh_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrh_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldrh	%s, [%s]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldrh	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_ldrh_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsb_immpostidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldrsb	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsb_immpreidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsb_immunsign, opc, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldrsb	%s, [%s]\n", pc, insn,
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldrsb	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_ldrsb_reg, opc, Rm, option, shift, Rn, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsh_immpostidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldrsh	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 2));
}

static void
OPFUNC_DECL(op_ldrsh_immpreidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsh_immunsign, opc, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldrsh	%s, [%s]\n", pc, insn,
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldrsh	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_ldrsh_reg, opc, Rm, option, shift, Rn, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsw_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	ldrsw	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(1, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 4));
}

static void
OPFUNC_DECL(op_ldrsw_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsw_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	ldrsw	%s, [%s]\n", pc, insn,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	ldrsw	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 4));
	}
}

static void
OPFUNC_DECL(op_ldrsw_literal, imm19, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldrsw_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtr, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtrb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtrh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtrsb, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtrsh, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldtrsw, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldur, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldurb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldurh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldursb, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldursh, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldursw, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldxp, size, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldxr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldxrb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ldxrh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_lsl_imm, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: lsr_imm,ubfiz,ubfm,ubfx,uxtb,uxth */
	if ((imms != (bitwidth - 1)) && ((imms + 1) == immr)) {
		PRINTF("%12lx:\t%08x	lsl	%s, %s, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    imms);
	} else if (imms == (bitwidth - 1)) {
		PRINTF("%12lx:\t%08x	lsr	%s, %s, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    imms);
	} else if (imms < immr) {
		PRINTF("%12lx:\t%08x	ubfiz	%s, %s, #%lu, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else if (BFXPreferred(sf, 1, imms, immr)) {
		PRINTF("%12lx:\t%08x	ubfx	%s, %s, #%lu, #%lu\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms -immr + 1) & (bitwidth - 1));
	} else if ((immr == 0) && (imms == 7)) {
		PRINTF("%12lx:\t%08x	uxtb	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn));
	} else if ((immr == 0) && (imms == 15)) {
		PRINTF("%12lx:\t%08x	uxth	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn));
	} else {
		UNDEFINED(pc, insn, "unknown");
	}
}

static void
OPFUNC_DECL(op_lsl_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: lslv */

	/* "lsl" always the preferred disassembly */
	PRINTF("%12lx:\t%08x	lsl	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_lsr_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: lsrv */

	/* "lsr" always the preferred disassembly */
	PRINTF("%12lx:\t%08x	lsr	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_madd, sf, Rm, Ra, Rn, Rd, UNUSED5)
{
	/* ALIAS: mul */
	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	mul	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%12lx:\t%08x	madd	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    ZREGNAME(sf, Ra));
	}
}

static void
OPFUNC_DECL(op_mneg, sf, Rm, Ra, Rn, Rd, UNUSED5)
{
	/* ALIAS: msub */
	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	mneg	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%12lx:\t%08x	msub	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    ZREGNAME(sf, Ra));
	}
}

static void
OPFUNC_DECL(op_mov_bmimm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, immr, imms)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

#if 0
	/* to distinguish from mov_iwimm */
	if ((Rn == 31) && !MoveWidePreferred(sf, n, immr, imms)) {
#else
	/* same as objdump... */
	(void)MoveWidePreferred;
	if (Rn == 31) {
#endif
		PRINTF("%12lx:\t%08x	mov	%s, #0x%lx\n", pc, insn,
		    SREGNAME(sf, Rd),
		    DecodeBitMasks(sf, n, immr, imms));
	} else {
		/* ALIAS: orr_imm */
		PRINTF("%12lx:\t%08x	orr	%s, %s, #0x%lx	#XXX\n", pc, insn,
		    SREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, immr, imms));
	}
}

static void
OPFUNC_DECL(op_mov_iwimm, sf, hw, imm16, Rd, UNUSED4, UNUSED5)
{
	const uint64_t mask = (sf == 0) ? 0xffffffff : 0xffffffffffffffffUL;

	/* ALIAS: movn */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("%12lx:\t%08x	mov	%s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, ~imm16, 1) & mask);
	} else {
		const int shift = hw * 16;
		PRINTF("%12lx:\t%08x	movn	%s, #0x%lx, lsl #%d\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, ~imm16, 1) & mask, shift);
	}
}

static void
OPFUNC_DECL(op_mov_reg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: orr_reg */
	if ((Rn == 31) && (imm6 == 0)) {
		PRINTF("%12lx:\t%08x	mov	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		if (imm6 == 0) {
			PRINTF("%12lx:\t%08x	orr	%s, %s, %s\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	orr	%s, %s, %s, %s #%lu\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, "lsl", "lsr", "asr", "ror"),
			    imm6);
		}
	}
}

static void
OPFUNC_DECL(op_mov_wimm, sf, hw, imm16, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: movz */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("%12lx:\t%08x	mov	%s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		const int shift = hw * 16;
#if 0
		PRINTF("%12lx:\t%08x	movz	%s, #0x%lx, lsl #%d\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
#else
		/* same as objdump */
		PRINTF("%12lx:\t%08x	mov	%s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1) << shift);
#endif
	}
}

static void
OPFUNC_DECL(op_movk, sf, hw, imm16, Rd, UNUSED4, UNUSED5)
{
	const int shift = hw * 16;

	if (hw == 0) {
		PRINTF("%12lx:\t%08x	movk	%s, #0x%lx\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		PRINTF("%12lx:\t%08x	movk	%s, #0x%lx, lsl #%d\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
	}
}

static void
OPFUNC_DECL(op_mrs, o0, op1, CRn, CRm, op2, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_msr, o0, op1, CRn, CRm, op2, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_msr_imm, op1, CRm, op2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_mvn, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: orn */
	if (Rn == 31) {
		if (shift == 0) {
			PRINTF("%12lx:\t%08x	mvn	%s, %s\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	mvn	%s, %s, %s #lu\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, ",lsl", ", lsr", ", asr", ", ror"),
			    shift);
		}
	} else {
		if (shift == 0) {
			PRINTF("%12lx:\t%08x	orn	%s, %s, %s\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm));
		} else {
			PRINTF("%12lx:\t%08x	orn	%s, %s, %s, %s #lu\n", pc, insn,
			    ZREGNAME(sf, Rd),
			    ZREGNAME(sf, Rn),
			    ZREGNAME(sf, Rm),
			    SHIFTOP4(shift, ",lsl", ", lsr", ", asr", ", ror"),
			    shift);
		}
	}
}

static void
OPFUNC_DECL(op_neg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: sub_shiftreg */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_ngc, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: sbc */
	if (Rn == 31) {
		PRINTF("%12lx:\t%08x	ngc	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%12lx:\t%08x	sbc	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
}

static void
OPFUNC_DECL(op_ngcs, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: sbcs */
	if (Rn == 31) {
		PRINTF("%12lx:\t%08x	ngcs	%s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%12lx:\t%08x	sbcs	%s, %s, %s\n", pc, insn,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
}

static void
OPFUNC_DECL(op_prfm_imm, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	prfm	%s, [%s]\n", pc, insn,
		    PREFETCH(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	prfm	%s, [%s,#%ld]\n", pc, insn,
		    PREFETCH(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm12, 8));
	}
}

static void
OPFUNC_DECL(op_prfm_literal, imm19, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	prfm	%s, %lx\n", pc, insn,
	    PREFETCH(Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_prfm_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_prfum, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("%12lx:\t%08x	prfum	%s, [%s]\n", pc, insn,
		    PREFETCH(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	prfum	%s, [%s,#%ld]\n", pc, insn,
		    PREFETCH(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_rbit, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	rbit	%s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_ret, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (Rn == 30) {
		PRINTF("%12lx:\t%08x	ret\n", pc, insn);
	} else {
		PRINTF("%12lx:\t%08x	ret	%s\n", pc, insn,
		    ZREGNAME(1, Rn));
	}
}

static void
OPFUNC_DECL(op_rev, sf, x, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	rev	%s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_rev16, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	rev	%s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_rev32, Rn, Rd, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	rev	%s, %s\n", pc, insn,
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ror_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: rorv */

	/* "ror" always the preferred disassembly */
	PRINTF("%12lx:\t%08x	ror	%s, %s, %s\n", pc, insn,
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

static void
OPFUNC_DECL(op_sdiv, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	sdiv	%s, %s, %s\n", pc, insn,
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

static void
OPFUNC_DECL(op_smaddl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: smull */
	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	smaddl	%s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("%12lx:\t%08x	smaddl	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_smc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	smc	#0x%lx\n", pc, insn,
	    imm16);
}

static void
OPFUNC_DECL(op_smnegl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: smsubl */
	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	smnegl	%s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("%12lx:\t%08x	smsubl	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_smulh, Rm, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	smulh	%s, %s, %s\n", pc, insn,
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

static void
OPFUNC_DECL(op_stlr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stlrb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	/* ALIAS: stlrh */
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stlxp, size, Rs, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stlxr, size, Rs, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stlxrb, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stlxrh, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stnp, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("%12lx:\t%08x	stnp	%s, %s, [%s]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	stnp	%s, %s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_stp_postidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	stp	%s, %s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_stp_preidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	stp	%s, %s, [%s,#%ld]!\n", pc, insn,
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_stp_signed, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("%12lx:\t%08x	stp	%s, %s, [%s]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	stp	%s, %s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_str_immpostidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	str	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_str_immpreidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	str	%s, [%s,#%ld]!\n", pc, insn,
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_str_immunsign, size, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	str	%s, [%s]\n", pc, insn,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	str	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_str_reg, size, Rm, option, shift, Rn, Rt)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_strb_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	strb	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strb_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_strb_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	strb	%s, [%s]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	strb	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_strb_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_strh_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	strh	%s, [%s],#%ld\n", pc, insn,
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strh_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_strh_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("%12lx:\t%08x	strh	%s, [%s]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("%12lx:\t%08x	strh	%s, [%s,#%ld]\n", pc, insn,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_strh_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sttr, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sttrb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sttrh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stur, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sturb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sturh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stxp, size, Rs, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stxr, size, Rs, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stxrb, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_stxrh, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sub_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
}

static void
OPFUNC_DECL(op_sub_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	PRINTF("%12lx:\t%08x	sub	%s, %s, #0x%lx%s\n", pc, insn,
	    SREGNAME(sf, Rd),
	    SREGNAME(sf, Rn),
	    SignExtend(12, imm12, 1),
	    SHIFTOP2(shift, "", ", lsl #12"));
}

static void
OPFUNC_DECL(op_svc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	svc	#0x%lx\n", pc, insn,
	    imm16);
}

static void
OPFUNC_DECL(op_sysl, op1, CRn, CRm, op2, Rt, UNUSED5)
{
	PRINTF("%12lx:\t%08x	sysl	%s, #%lu, %s, %s, #%lu\n", pc, insn,
	    ZREGNAME(1, Rt),
	    op1,
	    CREGNAME(CRn),
	    CREGNAME(CRm),
	    op2);
}

static void
OPFUNC_DECL(op_tbnz, b5, b40, imm14, Rt, UNUSED4, UNUSED5)
{
	uint64_t bit = (b5 << 5) + b40;

	PRINTF("%12lx:\t%08x	tbnz	%s, #%lu, %lx\n", pc, insn,
	    ZREGNAME(b5, Rt),
	    bit,
	    SignExtend(14, imm14, 4) + pc);
}

static void
OPFUNC_DECL(op_tbz, b5, b40, imm14, Rt, UNUSED4, UNUSED5)
{
	uint64_t bit = (b5 << 5) + b40;

	PRINTF("%12lx:\t%08x	tbz	%s, #%lu, %lx\n", pc, insn,
	    ZREGNAME(b5, Rt),
	    bit,
	    SignExtend(14, imm14, 4) + pc);
}

static void
OPFUNC_DECL(op_udiv, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	udiv	%s, %s, %s\n", pc, insn,
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_umaddl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: umull */
	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	umull	%s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("%12lx:\t%08x	umaddl	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_umnegl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: umsubl */

	if (Ra == 31) {
		PRINTF("%12lx:\t%08x	umnegl	%s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("%12lx:\t%08x	umsubl	%s, %s, %s, %s\n", pc, insn,
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_umulh, Rm, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("%12lx:\t%08x	umulh	%s, %s, %s\n", pc, insn,
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

//static void
//OPFUNC_DECL(op_uxtb, immr, imms, Rn, Rd, UNUSED4, UNUSED5)
//{
//	/* ALIAS: uxth */
//	PRINTF("%12lx:\t%08x	.word\t0x%08x\t# %s:%d\n", pc, insn, insn, __func__, __LINE__);
//}

#include "table.h"

#define WIDTHMASK(w)	(0xffffffff >> (32 - (w)))

static void
disasm_insn(uint64_t loc, uint32_t insn)
{
	uint64_t args[INSN_MAXARG];
	unsigned int i, j;

	for (i = 0; i < __arraycount(insn_tables); i++) {
		if ((insn & insn_tables[i].mask) != insn_tables[i].code)
			continue;

		/* extract operands */
		for (j = 0; j < INSN_MAXARG; j++) {
			args[j] = (insn >> insn_tables[i].bitinfo[j].pos) &
			    WIDTHMASK(insn_tables[i].bitinfo[j].width);
		}
		insn_tables[i].opfunc(loc, insn,
		    args[0], args[1], args[2], args[3], args[4], args[5]);
		break;
	}
}



/*
 * for test
 */
char *printf_buffer = NULL;
size_t printf_size;

static int
test_printf(char const *fmt, ...)
{
		va_list ap;
		int ret;

		va_start(ap, fmt);
		if (printf_buffer != NULL) {
			ret = vsnprintf(printf_buffer, printf_size, fmt, ap);
		} else {
			ret = vprintf(fmt, ap);
		}
		va_end(ap);
		return ret;
}

int
disasm(uint64_t loc, void *insnp, char *buf, size_t bufsize)
{
	uint32_t insn;

	printf_buffer = buf;
	printf_size = bufsize;

	insn = *(uint32_t *)insnp;
	disasm_insn(loc, insn);

	printf_buffer = NULL;
	printf_size = 0;

	return sizeof(uint32_t);
}

#ifdef STANDALONE_TEST
int
main(int argc, char *argv[])
{
	disasm_insn(0x200101d34, 0xf81d0ff6);	//        str     x22, [sp,#-48]!
	disasm_insn(0x200101d38, 0xa90153f5);	//        stp     x21, x20, [sp,#16]
	disasm_insn(0x200101d3c, 0xa9027bf3);	//        stp     x19, x30, [sp,#32]
	disasm_insn(0x200101d40, 0xaa0203f3);	//        mov     x19, x2
	disasm_insn(0x200101d44, 0xb40009b3);	//        cbz     x19, 200101e78 <___start+0x144>
	disasm_insn(0x200101d48, 0x900000a8);	//        adrp    x8, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101d4c, 0xf941f908);	//        ldr     x8, [x8,#1008]
	disasm_insn(0x200101d50, 0x900000b4);	//        adrp    x20, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101d54, 0xf9000113);	//        str     x19, [x8]
	disasm_insn(0x200101d58, 0xf9400a68);	//        ldr     x8, [x19,#16]
	disasm_insn(0x200101d5c, 0xf941fe94);	//        ldr     x20, [x20,#1016]
	disasm_insn(0x200101d60, 0xf9000288);	//        str     x8, [x20]
	disasm_insn(0x200101d64, 0xf9400268);	//        ldr     x8, [x19]
	disasm_insn(0x200101d68, 0xf9400109);	//        ldr     x9, [x8]
	disasm_insn(0x200101d6c, 0xb4000209);	//        cbz     x9, 200101dac <___start+0x78>
	disasm_insn(0x200101d70, 0x900000a8);	//        adrp    x8, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101d74, 0xf941ed08);	//        ldr     x8, [x8,#984]
	disasm_insn(0x200101d78, 0xf9000109);	//        str     x9, [x8]
	disasm_insn(0x200101d7c, 0xf9400269);	//        ldr     x9, [x19]
	disasm_insn(0x200101d80, 0xf9400129);	//        ldr     x9, [x9]
	disasm_insn(0x200101d84, 0x14000002);	//        b       200101d8c <___start+0x58>
	disasm_insn(0x200101d88, 0x91000529);	//        add     x9, x9, #0x1
	disasm_insn(0x200101d8c, 0x3940012a);	//        ldrb    w10, [x9]
	disasm_insn(0x200101d90, 0x7100bd5f);	//        cmp     w10, #0x2f
	disasm_insn(0x200101d94, 0x54000060);	//        b.eq    200101da0 <___start+0x6c>
	disasm_insn(0x200101d98, 0x35ffff8a);	//        cbnz    w10, 200101d88 <___start+0x54>
	disasm_insn(0x200101d9c, 0x14000009);	//        b       200101dc0 <___start+0x8c>
	disasm_insn(0x200101da0, 0x91000529);	//        add     x9, x9, #0x1
	disasm_insn(0x200101da4, 0xf9000109);	//        str     x9, [x8]
	disasm_insn(0x200101da8, 0x17fffff9);	//        b       200101d8c <___start+0x58>
	disasm_insn(0x200101dac, 0x900000a8);	//        adrp    x8, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101db0, 0xf941ed08);	//        ldr     x8, [x8,#984]
	disasm_insn(0x200101db4, 0x900000a9);	//        adrp    x9, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101db8, 0x9121e129);	//        add     x9, x9, #0x878
	disasm_insn(0x200101dbc, 0xf9000109);	//        str     x9, [x8]
	disasm_insn(0x200101dc0, 0x900000a8);	//        adrp    x8, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101dc4, 0xf941f108);	//        ldr     x8, [x8,#992]
	disasm_insn(0x200101dc8, 0xb4000168);	//        cbz     x8, 200101df4 <___start+0xc0>
	disasm_insn(0x200101dcc, 0xb4000621);	//        cbz     x1, 200101e90 <___start+0x15c>
	disasm_insn(0x200101dd0, 0xb9400028);	//        ldr     w8, [x1]
	disasm_insn(0x200101dd4, 0x52970f49);	//        mov     w9, #0xb87a                     // #47226
	disasm_insn(0x200101dd8, 0x72baaa09);	//        movk    w9, #0xd550, lsl #16
	disasm_insn(0x200101ddc, 0x6b09011f);	//        cmp     w8, w9
	disasm_insn(0x200101de0, 0x54000641);	//        b.ne    200101ea8 <___start+0x174>
	disasm_insn(0x200101de4, 0xb9400428);	//        ldr     w8, [x1,#4]
	disasm_insn(0x200101de8, 0x7100051f);	//        cmp     w8, #0x1
	disasm_insn(0x200101dec, 0x540006a1);	//        b.ne    200101ec0 <___start+0x18c>
	disasm_insn(0x200101df0, 0x97ffff8c);	//        bl      200101c20 <atexit@plt>
	disasm_insn(0x200101df4, 0x97ffffa7);	//        bl      200101c90 <_libc_init@plt>
	disasm_insn(0x200101df8, 0x900000b5);	//        adrp    x21, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101dfc, 0xf941f6b5);	//        ldr     x21, [x21,#1000]
	disasm_insn(0x200101e00, 0x900000a8);	//        adrp    x8, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101e04, 0x91086108);	//        add     x8, x8, #0x218
	disasm_insn(0x200101e08, 0xeb15011f);	//        cmp     x8, x21
	disasm_insn(0x200101e0c, 0x540000e2);	//        b.cs    200101e28 <___start+0xf4>
	disasm_insn(0x200101e10, 0x900000b6);	//        adrp    x22, 200115000 <__EH_FRAME_END__+0xfdf0>
	disasm_insn(0x200101e14, 0x910862d6);	//        add     x22, x22, #0x218
	disasm_insn(0x200101e18, 0xf84086c8);	//        ldr     x8, [x22],#8
	disasm_insn(0x200101e1c, 0xd63f0100);	//        blr     x8
	disasm_insn(0x200101e20, 0xeb1502df);	//        cmp     x22, x21
}
#endif
