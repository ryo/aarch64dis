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

static int test_printf(char const *fmt, ...);
#define PRINTF	test_printf


#define OPFUNC_DECL(func,a,b,c,d,e,f)		\
func(uint64_t pc, uint32_t insn,		\
     uint64_t a, uint64_t b, uint64_t c,	\
     uint64_t d, uint64_t e, uint64_t f)

struct bitpos {
	uint8_t pos;
	uint8_t width;
};

struct aarch64_insn_info {
	uint32_t mask;
	uint32_t code;
#define INSN_MAXARG	6
	struct bitpos bitinfo[INSN_MAXARG];
	OPFUNC_DECL(void (*opfunc),,,,,,);
};

#define UNUSED1	arg1 __unused
#define UNUSED2	arg2 __unused
#define UNUSED3	arg3 __unused
#define UNUSED4	arg4 __unused
#define UNUSED5	arg5 __unused
#define UNUSED6	arg6 __unused

static const char *z_wxregs[2][32] = {
	{
		 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
		 "w8",  "w9", "w10", "w11", "w12", "w13", "w14", "w15",
		"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
		"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"
	},
	{
		 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		 "x8",  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"
	}
};

static const char *s_wxregs[2][32] = {
	{
		 "w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
		 "w8",  "w9", "w10", "w11", "w12", "w13", "w14", "w15",
		"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
		"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wsp"
	},
	{
		 "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		 "x8",  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30",  "sp"
	}
};
#define ZREGNAME(s, n)	(z_wxregs[(s) & 1][(n) & 31])
#define SREGNAME(s, n)	(s_wxregs[(s) & 1][(n) & 31])

static const char *cregs[16] = {
	 "C0",  "C1",  "C2",  "C3",  "C4",  "C5",  "C6",  "C7",
	 "C8",  "C9", "C10", "C11", "C12", "C13", "C14", "C15"
};
#define CREGNAME(n)	cregs[(n) & 15]

static const char *conditioncode[16] = {
	"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt",
	"gt", "le", "al", "nv"
};
#define CONDNAME(c)	conditioncode[(c) & 15]
#define IVCONDNAME(c)	conditioncode[((c) ^ 1) & 15]

static const char *barrierop[16] = {
	 "#0", "oshld", "oshst", "osh",
	 "#4", "nshld", "nshst", "nsh",
	 "#8", "ishld", "ishst", "ish",
	"#12",    "ld",    "st",  "sy"
};
#define BARRIERNAME(op)	barrierop[(op) & 15]

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
#define PREFETCHNAME(op)	prefetchop[(op) & 31]


#include "sysreg.h"

static const char *
sysregname_bsearch(uint32_t code)
{
	struct sysreg_table *base, *p;
	unsigned int lim;
	int32_t cmp;

	base = sysreg_table;
	for (lim = __arraycount(sysreg_table); lim != 0; lim >>= 1) {
		p = base + (lim >> 1);
		cmp = code - p->code;
		if (cmp == 0)
			return p->regname;
		if (cmp > 0) {
			base = p + 1;
			lim--;
		}
	}
	return NULL;
}

#define SYSREG_OP_READ	0x01
#define SYSREG_OP_WRITE	0x02

static const char *
sysregname(char *buf, size_t buflen, uint32_t rw,
           uint64_t op0, uint64_t op1, uint64_t CRn, uint64_t CRm, uint64_t op2)
{
	const char *name;
	uint32_t code;

	code = SYSREG_ENC(op0, op1, CRn, CRm, op2);

	/* special case for dbgdtrrx_el0(RO) and dbgdtrtx_el0(WO) */
	if (code == SYSREG_ENC(2,3,0,5,0)) {
		if (rw & SYSREG_OP_WRITE)
			return "dbgdtrtx_el0";
		return "dbgdtrrx_el0";
	}

	name = sysregname_bsearch(code);
	if (name == NULL) {
#define SYSREGNAMEBUFLEN	sizeof("s99_99_c99_c99_99")
		snprintf(buf, buflen, "s%lu_%lu_c%lu_c%lu_%lu",
		    op0, op1, CRn, CRm, op2);
		return buf;
	}
	return name;
}
#define RSYSREGNAME(buf, buflen, op0, op1, CRn, CRm, op2)		\
	sysregname(buf, buflen, SYSREG_OP_READ, op0, op1, CRn, CRm, op2)
#define WSYSREGNAME(buf, buflen, op0, op1, CRn, CRm, op2)		\
	sysregname(buf, buflen, SYSREG_OP_WRITE, op0, op1, CRn, CRm, op2)


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
	uint64_t result;

	n &= (bitwidth - 1);
	result = (((v << (bitwidth - n)) | (v >> n)));
	if (bitwidth < 64)
		result &= ((1UL << bitwidth) - 1);
	return result;
}

static bool
MoveWidePreferred(uint64_t sf, uint64_t n, uint64_t immr, uint64_t imms)
{
	const int bitwidth = (sf == 0) ? 32 : 64;

	if ((sf != 0) && (n == 0))
		return false;
	if ((sf == 0) && ((n != 0) || (immr > 0x1f)))
		return false;
	if (imms < 16)
		return ((-immr & 15) <= (15 - imms));
	if (imms >= (uint64_t)(bitwidth - 15))
		return ((immr & 15) <= (imms - (bitwidth - 15)));
	return false;
}

static bool
ValidBitMasks(uint64_t sf, uint64_t n, uint64_t imms, uint64_t immr)
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
DecodeBitMasks(uint64_t sf, uint64_t n, uint64_t imms, uint64_t immr)
{
	const int bitwidth = (sf == 0) ? 32 : 64;
	uint64_t result;
	int esize, len;

	len = fls64((n << 6) + (~imms & 0x3f)) - 1;
	esize = (1 << len);
	imms &= (esize - 1);
	immr &= (esize - 1);
	result = rotate(esize, (1ULL << (imms + 1)) - 1, immr);
	while (esize < bitwidth) {
		result |= (result << esize);
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

#define SHIFTOP2(s, op1, op2)					\
	((const char *[]){ op1, op2 })[(s) & 1]
#define SHIFTOP4(s, op1, op2, op3, op4)				\
	((const char *[]){ op1, op2, op3, op4 })[(s) & 3]
#define SHIFTOP8(s, op1, op2, op3, op4, op5, op6, op7, op8)	\
	((const char *[]){ op1, op2, op3, op4, op5, op6, op7, op8 })[(s) & 7]

static const char *
DecodeShift(uint64_t shift)
{
	return SHIFTOP4(shift, "lsl", "lsr", "asr", "ror");
}

#define UNDEFINED(pc, insn, comment)	\
	PRINTF(".word\t0x%08x\t# %s\n", insn, comment);

static void
extendreg_common(const char *op, const char *z_op,
                 uint64_t pc, uint32_t insn, uint64_t sf, uint64_t Rm,
                 uint64_t option, uint64_t imm3, uint64_t Rn, uint64_t Rd)
{
	const int r = (sf == 0) ? 0 : ((option & 3) == 3) ? 1 : 0;

	if ((z_op != NULL) && (Rd == 31)) {
		PRINTF("%s\t", z_op);
	} else {
		PRINTF("%s\t%s, ", op, SREGNAME(sf, Rd));
	}

	PRINTF("%s, %s", SREGNAME(sf, Rn), ZREGNAME(r, Rm));

	if ((Rd == 31) || (Rn == 31)) {
		if (imm3 == 0) {
			if (!((sf == 0) && (option == 2)) &&
			    !((sf != 0) && (option == 3))) {
				PRINTF(", %s",
				    SHIFTOP8(option,
				    "uxtb", "uxth", "uxtw", "uxtx",
				    "sxtb", "sxth", "sxtw", "sxtx"));
			}
		} else {
			PRINTF(", %s #%lu",
			    SHIFTOP8(option,
			    "uxtb", "uxth", "lsl", "lsl",
			    "sxtb", "sxth", "sxtw", "sxtx"),
			    imm3);
		}
	} else {
		PRINTF(", %s",
		    SHIFTOP8(option,
		    "uxtb", "uxth", "uxtw", "uxtx",
		    "sxtb", "sxth", "sxtw", "sxtx"));
		if (imm3 != 0)
			PRINTF(" #%lu", imm3);
	}
	PRINTF("\n");
}

static void
shiftreg_common(const char *dnm_op, const char *dzm_op, const char *znm_op,
                uint64_t pc, uint32_t insn, uint64_t sf, uint64_t shift,
                uint64_t Rm, uint64_t imm6, uint64_t Rn, uint64_t Rd)
{
	if ((sf == 0) && (imm6 >= 32)) {
		UNDEFINED(pc, insn, "illegal imm6");
		return;
	}

	if ((dzm_op != NULL) && (Rn == 31)) {
		PRINTF("%s\t%s, %s",
		    dzm_op,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else if ((znm_op != NULL) && (Rd == 31)) {
		PRINTF("%s\t%s, %s",
		    znm_op,
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("%s\t%s, %s, %s",
		    dnm_op,
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
	if (imm6 != 0)
		PRINTF(", %s #%lu", DecodeShift(shift), imm6);
	PRINTF("\n");
}

static inline int
regoffset_option_to_r(uint64_t option)
{
	switch (option) {
	case 2:
	case 6:
		return 0;
	case 3:
	case 7:
		return 1;
	default:
		return -1;
	}
}

static void
regoffset_b_common(const char *op,
                   uint64_t pc, uint32_t insn,
                   uint64_t Rm, uint64_t option, uint64_t shift,
                   uint64_t Rn, uint64_t Rt)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%lu]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    0);
	}
}

static void
regoffset_h_common(const char *op,
                   uint64_t pc, uint32_t insn,
                   uint64_t Rm, uint64_t option, uint64_t shift,
                   uint64_t Rn, uint64_t Rt)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if ((shift == 0) && (option == 3)) {
		PRINTF("%s\t%s, [%s,%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm));
	} else if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s,%s]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%lu]\n",
		    op,
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    shift);
	}
}

static void
regoffset_w_common(const char *op,
                   uint64_t pc, uint32_t insn,
                   uint64_t Rm, uint64_t option, uint64_t shift,
                   uint64_t Rn, uint64_t Rt)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if ((shift == 0) && (option == 3)) {
		PRINTF("%s\t%s, [%s,%s]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm));
	} else if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s,%s]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"));
	} else {
		PRINTF("%s\t%s, [%s,%s,%s #%lu]\n",
		    op,
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    shift * 2);
	}
}

static void
regoffset_x_common(const char *op,
                   uint64_t pc, uint32_t insn,
                   uint64_t size, uint64_t Rm, uint64_t option, uint64_t shift,
                   uint64_t Rn, uint64_t Rt)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("%s\t%s, [%s,%s%s]\n",
		    op,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		uint64_t amount = 2 + size;
		PRINTF("%s\t%s, [%s,%s,%s #%lu]\n",
		    op,
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    amount);
	}
}

static void
OPFUNC_DECL(op_undefined, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	UNDEFINED(pc, insn, "undefined");
}

static void
OPFUNC_DECL(op_adc, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("adc\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_adcs, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("adcs\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_add_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	extendreg_common("add", NULL,
	    pc, insn, sf, Rm, option, imm3, Rn, Rd);
}

static void
OPFUNC_DECL(op_add_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: mov_tofromsp */
	if ((Rd == 31 || Rn == 31) && (imm12 == 0)) {
		PRINTF("mov\t%s, %s\n",
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn));
	} else {
		PRINTF("add\t%s, %s, #0x%lx%s\n",
		    SREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "?", "?"));
	}
}

static void
OPFUNC_DECL(op_add_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}
	shiftreg_common("add", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_adds_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: cmn_extreg */
	extendreg_common("adds", "cmn",
	    pc, insn, sf, Rm, option, imm3, Rn, Rd);
}

static void
OPFUNC_DECL(op_adds_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: cmn_imm */
	if (Rd == 31) {
		PRINTF("cmn\t%s, #0x%lx%s\n",
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	} else {
		PRINTF("adds\t%s, %s, #0x%lx%s\n",
		    ZREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP4(shift, "", ", lsl #12", "", ""));
	}
}

static void
OPFUNC_DECL(op_adds_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}
	/* ALIAS: cmn_shiftreg */
	shiftreg_common("adds", NULL, "cmn", pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_adr, immlo, immhi, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("adr\t%s, %lx\n",
	    ZREGNAME(1, Rd),
	    SignExtend(21, imm, 1) + pc);
}

static void
OPFUNC_DECL(op_adrp, immlo, immhi, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	uint64_t imm = ((immhi << 2) | immlo);

	PRINTF("adrp\t%s, %lx\n",
	    ZREGNAME(1, Rd),
	    SignExtend(21, imm, 4096) + (pc & -4096));
}

static void
OPFUNC_DECL(op_and_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("and\t%s, %s, #0x%lx\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, imms, immr));
}

static void
OPFUNC_DECL(op_and_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common("and", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_ands_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	/* ALIAS: tst_imm */
	if (Rd == 31) {
		PRINTF("tst\t%s, #0x%lx\n",
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	} else {
		PRINTF("ands\t%s, %s, #0x%lx\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	}
}

static void
OPFUNC_DECL(op_ands_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: tst_shiftreg */
	shiftreg_common("ands", NULL, "tst", pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_asr_imm, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: sbfiz,sbfm,sbfx,sxtb,sxth,sxtw */
	if ((imms != (bitwidth - 1)) && ((imms + 1) == immr)) {
		PRINTF("asr\t%s, %s, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    bitwidth - immr);
	} else if (imms == (bitwidth - 1)) {
		PRINTF("asr\t%s, %s, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr);
	} else if (imms < immr) {
		PRINTF("sbfiz\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else if (BFXPreferred(sf, 0, imms, immr)) {
		PRINTF("sbfx\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms - immr + 1) & (bitwidth - 1));
	} else if ((immr == 0) && (imms == 7)) {
		PRINTF("sxtb\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 15)) {
		PRINTF("sxth\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 31)) {
		PRINTF("sxtw\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(0, Rn));
	} else {
		UNDEFINED(pc, insn, "unknown");
	}
}

static void
OPFUNC_DECL(op_asr_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: asrv */
	/* "asr" always the preferred disassembly */
	PRINTF("asr\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

struct op_sys_table {
	uint32_t code;
	int flags;
#define OPE_NONE	0x00000000
#define OPE_XT		0x00000001
	const char *opname;
};

static struct op_sys_table op_sys_table[] = {
	{ SYSREG_ENC(1, 0, 7,  1, 0), OPE_NONE,	"ic\tialluis"		},
	{ SYSREG_ENC(1, 0, 7,  1, 0), OPE_NONE,	"ic\tialluis"		},
	{ SYSREG_ENC(1, 0, 7,  5, 0), OPE_NONE,	"ic\tiallu"		},
	{ SYSREG_ENC(1, 3, 7,  5, 1), OPE_XT,	"ic\tivau"		},
	{ SYSREG_ENC(1, 0, 7,  6, 1), OPE_XT,	"dc\tivac"		},
	{ SYSREG_ENC(1, 0, 7,  6, 2), OPE_XT,	"dc\tisw"		},
	{ SYSREG_ENC(1, 0, 7, 10, 2), OPE_XT,	"dc\tcsw"		},
	{ SYSREG_ENC(1, 0, 7, 14, 2), OPE_XT,	"dc\tcisw"		},
	{ SYSREG_ENC(1, 3, 7, 10, 1), OPE_XT,	"dc\tcvac"		},
	{ SYSREG_ENC(1, 3, 7, 11, 1), OPE_XT,	"dc\tcvau"		},
	{ SYSREG_ENC(1, 3, 7, 14, 1), OPE_XT,	"dc\tcivac"		},
	{ SYSREG_ENC(1, 3, 7,  4, 1), OPE_XT,	"dc\tzva"		},
	{ SYSREG_ENC(1, 0, 7,  8, 0), OPE_XT,	"at\ts1e1r"		},
	{ SYSREG_ENC(1, 0, 7,  8, 1), OPE_XT,	"at\ts1e1w"		},
	{ SYSREG_ENC(1, 0, 7,  8, 2), OPE_XT,	"at\ts1e0r"		},
	{ SYSREG_ENC(1, 0, 7,  8, 3), OPE_XT,	"at\ts1e0w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 0), OPE_XT,	"at\ts1e2r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 1), OPE_XT,	"at\ts1e2w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 4), OPE_XT,	"at\ts12e1r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 5), OPE_XT,	"at\ts12e1w"		},
	{ SYSREG_ENC(1, 4, 7,  8, 6), OPE_XT,	"at\ts12e0r"		},
	{ SYSREG_ENC(1, 4, 7,  8, 7), OPE_XT,	"at\ts12e0w"		},
	{ SYSREG_ENC(1, 6, 7,  8, 0), OPE_XT,	"at\ts1e3r"		},
	{ SYSREG_ENC(1, 6, 7,  8, 1), OPE_XT,	"at\ts1e3w"		},
	{ SYSREG_ENC(1, 0, 8,  3, 0), OPE_NONE,	"tlbi\tvmalle1is"	},
	{ SYSREG_ENC(1, 0, 8,  3, 1), OPE_XT,	"tlbi\tvae1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 2), OPE_XT,	"tlbi\taside1is"	},
	{ SYSREG_ENC(1, 0, 8,  3, 3), OPE_XT,	"tlbi\tvaae1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 5), OPE_XT,	"tlbi\tvale1is"		},
	{ SYSREG_ENC(1, 0, 8,  3, 7), OPE_XT,	"tlbi\tvaale1is"	},
	{ SYSREG_ENC(1, 0, 8,  7, 0), OPE_NONE,	"tlbi\tvmalle1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 1), OPE_XT,	"tlbi\tvae1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 2), OPE_XT,	"tlbi\taside1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 3), OPE_XT,	"tlbi\tvaae1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 5), OPE_XT,	"tlbi\tvale1"		},
	{ SYSREG_ENC(1, 0, 8,  7, 7), OPE_XT,	"tlbi\tvaale1"		},
	{ SYSREG_ENC(1, 4, 8,  0, 1), OPE_XT,	"tlbi\tipas2e1is"	},
	{ SYSREG_ENC(1, 4, 8,  0, 5), OPE_XT,	"tlbi\tipas2le1is"	},
	{ SYSREG_ENC(1, 4, 8,  3, 0), OPE_NONE,	"tlbi\talle2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 1), OPE_XT,	"tlbi\tvae2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 4), OPE_NONE,	"tlbi\talle1is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 5), OPE_XT,	"tlbi\tvale2is"		},
	{ SYSREG_ENC(1, 4, 8,  3, 6), OPE_NONE,	"tlbi\tvmalls12e1is"	},
	{ SYSREG_ENC(1, 4, 8,  4, 1), OPE_XT,	"tlbi\tipas2e1"		},
	{ SYSREG_ENC(1, 4, 8,  4, 5), OPE_XT,	"tlbi\tipas2le1"	},
	{ SYSREG_ENC(1, 4, 8,  7, 0), OPE_NONE,	"tlbi\talle2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 1), OPE_XT,	"tlbi\tvae2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 4), OPE_NONE,	"tlbi\talle1"		},
	{ SYSREG_ENC(1, 4, 8,  7, 5), OPE_XT,	"tlbi\tvale2"		},
	{ SYSREG_ENC(1, 4, 8,  7, 6), OPE_NONE,	"tlbi\tvmalls12e1"	},
	{ SYSREG_ENC(1, 6, 8,  3, 0), OPE_NONE,	"tlbi\talle3is"		},
	{ SYSREG_ENC(1, 6, 8,  3, 1), OPE_XT,	"tlbi\tvae3is"		},
	{ SYSREG_ENC(1, 6, 8,  3, 5), OPE_XT,	"tlbi\tvale3is"		},
	{ SYSREG_ENC(1, 6, 8,  7, 0), OPE_NONE,	"tlbi\talle3"		},
	{ SYSREG_ENC(1, 6, 8,  7, 1), OPE_XT,	"tlbi\tvae3"		},
	{ SYSREG_ENC(1, 6, 8,  7, 5), OPE_XT,	"tlbi\tvale3"		}
};

static void
OPFUNC_DECL(op_at, op1, CRn, CRm, op2, Rt, UNUSED5)
{
	uint32_t code;
	size_t i;

	/* ALIAS: dc,ic,sys,tlbi */
	code = SYSREG_ENC(1, op1, CRn, CRm, op2);
	for (i = 0; i < __arraycount(op_sys_table); i++) {
		if (op_sys_table[i].code != code)
			continue;

		if (((op_sys_table[i].flags & OPE_XT) != 0) &&
		    (Rt != 31)) {
			PRINTF("%s, %s\n",
			    op_sys_table[i].opname,
			    ZREGNAME(1, Rt));
		} else if (Rt != 31) {
#if 0
			/* Rt suppressed, but Rt field is not a xzr */
			UNDEFINED(pc, insn, "illegal Rt");
#else
			/* fallback to sys instruction */
			continue;
#endif
		} else {
			PRINTF("%s\n",
			    op_sys_table[i].opname);
		}
		return;
	}

	/* default, sys instruction */
	PRINTF("sys\t#%lu, %s, %s, #%lu, %s\n",
	    op1,
	    CREGNAME(CRn),
	    CREGNAME(CRm),
	    op2,
	    ZREGNAME(1,Rt));
}

static void
OPFUNC_DECL(op_b, imm26, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("b\t%lx\n", SignExtend(26, imm26, 4) + pc);
}

static void
OPFUNC_DECL(op_b_cond, imm19, cond, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("b.%s\t%lx\n",
	    CONDNAME(cond),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_bfi, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: bfm,bfxil */
	/* it is not disassembled as bfm */
	if (imms < immr) {
		PRINTF("bfi\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else {
		PRINTF("bfxil\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms -immr + 1) & (bitwidth - 1));
	}
}

static void
OPFUNC_DECL(op_bic_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common("bic", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_bics_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common("bics", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_bl, imm26, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("bl\t%lx\n", SignExtend(26, imm26, 4) + pc);
}

static void
OPFUNC_DECL(op_blr, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("blr\t%s\n", ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_br, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("br\t%s\n", ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_brk, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("brk\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_cbnz, sf, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("cbnz\t%s, %lx\n",
	    ZREGNAME(sf, Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_cbz, sf, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("cbz\t%s, %lx\n",
	    ZREGNAME(sf, Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_ccmn_imm, sf, imm5, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("ccmn\t%s, #0x%lx, #0x%lx, %s\n",
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    CONDNAME(cond));
}

static void
OPFUNC_DECL(op_ccmn_reg, sf, Rm, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("ccmn\t%s, %s, #0x%lx, %s\n",
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    CONDNAME(cond));
}

static void
OPFUNC_DECL(op_ccmp_imm, sf, imm5, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("ccmp\t%s, #0x%lx, #0x%lx, %s\n",
	    ZREGNAME(sf, Rn),
	    imm5,
	    nzcv,
	    CONDNAME(cond));
}

static void
OPFUNC_DECL(op_ccmp_reg, sf, Rm, cond, Rn, nzcv, UNUSED5)
{
	PRINTF("ccmp\t%s, %s, #0x%lx, %s\n",
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    nzcv,
	    CONDNAME(cond));
}

static void
OPFUNC_DECL(op_cinc, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: cset,csinc */
	if ((Rn == Rm) && (Rn != 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("cinc\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCONDNAME(cond));
	} else if ((Rn == Rm) && (Rn == 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("cset\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    IVCONDNAME(cond));
	} else {
		PRINTF("csinc\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    CONDNAME(cond));
	}
}

static void
OPFUNC_DECL(op_cinv, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: csetm,csinv */
	if ((Rn == Rm) && (Rn != 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("cinv\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCONDNAME(cond));
	} else if ((Rn == Rm) && (Rn == 31) && ((cond & 0xe) != 0x0e)) {
		PRINTF("csetm\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    IVCONDNAME(cond));
	} else {
		PRINTF("csinv\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    CONDNAME(cond));
	}
}

static void
OPFUNC_DECL(op_clrex, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (CRm == 15) {
		PRINTF("clrex\n");
	} else {
		PRINTF("clrex\t#d\n", CRm);
	}
}

static void
OPFUNC_DECL(op_cls, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("cls\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_clz, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("clz\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_cmp_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	/* ALIAS: subs_extreg */
	extendreg_common("subs", "cmp",
	    pc, insn, sf, Rm, option, imm3, Rn, Rd);
}

static void
OPFUNC_DECL(op_cmp_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: subs_imm */
	if (Rd == 31) {
		PRINTF("cmp\t%s, #0x%lx%s\n",
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP2(shift, "", ", lsl #12"));
	} else {
		PRINTF("subs\t%s, %s, #0x%lx%s\n",
		    ZREGNAME(sf, Rd),
		    SREGNAME(sf, Rn),
		    ZeroExtend(12, imm12, 1),
		    SHIFTOP2(shift, "", ", lsl #12"));
	}
}

static void
OPFUNC_DECL(op_cmp_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	if (shift == 3) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	/* ALIAS: negs,subs_shiftreg */
	shiftreg_common("subs", "negs", "cmp", pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_cneg, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	/* ALIAS: csneg */
	if ((Rn == Rm) && ((cond & 0xe) != 0x0e)) {
		PRINTF("cneg\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    IVCONDNAME(cond));
	} else {
		PRINTF("csneg\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    CONDNAME(cond));
	}
}

static void
crc32w_common(const char *op,
              uint64_t pc, uint32_t insn,
              uint64_t sf, uint64_t Rm, uint64_t Rn, uint64_t Rd)
{
	if (sf != 0) {
		UNDEFINED(pc, insn, "illegal size");
		return;
	}

	PRINTF("%s\t%s, %s, %s\n",
	    op,
	    ZREGNAME(0, Rd),
	    ZREGNAME(0, Rn),
	    ZREGNAME(0, Rm));
}

static void
crc32x_common(const char *op,
              uint64_t pc, uint32_t insn,
              uint64_t sf, uint64_t Rm, uint64_t Rn, uint64_t Rd)
{
	if (sf == 0) {
		UNDEFINED(pc, insn, "illegal size");
		return;
	}

	PRINTF("%s\t%s, %s, %s\n",
	    op,
	    ZREGNAME(0, Rd),
	    ZREGNAME(0, Rn),
	    ZREGNAME(1, Rm));
}


static void
OPFUNC_DECL(op_crc32b, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32b", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32cb, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32cb", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32ch, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32ch", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32cw, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32cw", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32cx, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32cx", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32h, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32h", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32w, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32w_common("crc32w", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_crc32x, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	crc32x_common("crc32x", pc, insn, sf, Rm, Rn, Rd);
}

static void
OPFUNC_DECL(op_csel, sf, Rm, cond, Rn, Rd, UNUSED5)
{
	PRINTF("csel\t%s, %s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm),
	    CONDNAME(cond));
}

static void
OPFUNC_DECL(op_dcps1, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0)
		PRINTF("dpcs1\n");
	else
		PRINTF("dpcs1\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_dcps2, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0)
		PRINTF("dpcs2\n");
	else
		PRINTF("dpcs2\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_dcps3, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm16 == 0)
		PRINTF("dpcs3\n");
	else
		PRINTF("dpcs3\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_dmb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("dmb\t%s\n", BARRIERNAME(CRm));
}

static void
OPFUNC_DECL(op_drps, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("drps\n");
}

static void
OPFUNC_DECL(op_dsb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("dsb\t%s\n", BARRIERNAME(CRm));
}

static void
OPFUNC_DECL(op_eon_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common("eon", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_eor_imm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	PRINTF("eor\t%s, %s, #0x%lx\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    DecodeBitMasks(sf, n, imms, immr));
}

static void
OPFUNC_DECL(op_eor_shiftreg, sf, shift, Rm, imm6, Rn, Rd)
{
	shiftreg_common("eor", NULL, NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_eret, UNUSED0, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("eret\n", insn);
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
		PRINTF("ror\t%s, %s, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    imms);
	} else {
		PRINTF("extr\t%s, %s, %s, #%lu\n",
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
		PRINTF("nop\n");
		break;
	case 1:
		PRINTF("yield\n");
		break;
	case 2:
		PRINTF("wfe\n");
		break;
	case 3:
		PRINTF("wfi\n");
		break;
	case 4:
		PRINTF("sev\n");
		break;
	case 5:
		PRINTF("sevl\n");
		break;
	}
}

static void
OPFUNC_DECL(op_hlt, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("hlt\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_hvc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("hvc\t#0x%lx\n", imm16);
}

static void
OPFUNC_DECL(op_isb, CRm, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (CRm == 15)
		PRINTF("isb\n");
	else
		PRINTF("isb\t#d\n", CRm);
}

static void
OPFUNC_DECL(op_ldar, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldar\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldarb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldarb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldarh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldarh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldaxp, size, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldaxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldaxr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldaxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldaxrb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldaxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldaxrh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldaxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldnp, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("ldnp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldnp\t%s, %s, [%s,#%ld]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldp_postidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("ldp\t%s, %s, [%s],#%ld\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_ldp_preidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("ldp\t%s, %s, [%s,#%ld]!\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_ldp_signed, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("ldp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldp\t%s, %s, [%s,#%ld]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldpsw_postidx, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldpsw\t%s, %s, [%s],#%ld\n",
	    ZREGNAME(1, Rt),
	    ZREGNAME(1, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, 4));
}

static void
OPFUNC_DECL(op_ldpsw_preidx, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldpsw\t%s, %s, [%s,#%ld]!\n",
	    ZREGNAME(1, Rt),
	    ZREGNAME(1, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, 4));
}

static void
OPFUNC_DECL(op_ldpsw_signed, imm7, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("ldpsw\t%s, %s, [%s]\n",
		    ZREGNAME(1, Rt),
		    ZREGNAME(1, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldpsw\t%s, %s, [%s,#%ld]\n",
		    ZREGNAME(1, Rt),
		    ZREGNAME(1, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, 4));
	}
}

static void
OPFUNC_DECL(op_ldr_immpostidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldr\t%s, [%s],#%ld\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldr_immpreidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldr\t%s, [%s,#%ld]!\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldr_immunsign, size, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldr\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_ldr_literal, size, imm19, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldr\t%s, %lx\n",
	    ZREGNAME(size, Rt),
	    SignExtend(19, imm19, 4) + pc);

}

static void
OPFUNC_DECL(op_ldr_reg, size, Rm, option, shift, Rn, Rt)
{
	regoffset_x_common("ldr", pc, insn, size, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldrb_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrb\t%s, [%s],#%ld\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrb_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrb\t%s, [%s,#%ld]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrb_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_ldrb_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	regoffset_b_common("ldrb", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldrh_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrh\t%s, [%s],#%ld\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrh_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrh\t%s, [%s,#%ld]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrh_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_ldrh_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	regoffset_h_common("ldrh", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldrsb_immpostidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldrsb\t%s, [%s],#%ld\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsb_immpreidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldrsb\t%s, [%s,#%ld]!\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsb_immunsign, opc, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldrsb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsb\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_ldrsb_reg, opc, Rm, option, shift, Rn, Rt)
{
	regoffset_b_common("ldrsb", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldrsh_immpostidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldrsh\t%s, [%s],#%ld\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsh_immpreidx, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldrsh\t%s, [%s,#%ld]!\n",
	    ZREGNAME((opc ^ 1), Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsh_immunsign, opc, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldrsh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsh\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_ldrsh_reg, opc, Rm, option, shift, Rn, Rt)
{
	regoffset_h_common("ldrsh", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldrsw_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrsw\t%s, [%s],#%ld\n",
	    ZREGNAME(1, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsw_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrsw\t%s, [%s,#%ld]!\n",
	    ZREGNAME(1, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_ldrsw_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("ldrsw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldrsw\t%s, [%s,#%ld]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 4));
	}
}

static void
OPFUNC_DECL(op_ldrsw_literal, imm19, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldrsw\t%s, %lx\n",
	    ZREGNAME(1, Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_ldrsw_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	regoffset_w_common("ldrsw", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_ldtr, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtr\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldtrb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldtrh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldtrsb, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtrsb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsb\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldtrsh, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtrsh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsh\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldtrsw, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldtrsw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldtrsw\t%s, [%s,#%ld]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldur, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldur\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldur\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldurb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldurb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldurb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldurh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldurh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldurh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldursb, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldursb\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursb\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldursh, opc, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldursh\t%s, [%s]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursh\t%s, [%s,#%ld]\n",
		    ZREGNAME((opc ^ 1), Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldursw, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("ldursw\t%s, [%s]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("ldursw\t%s, [%s,#%ld]\n",
		    ZREGNAME(1, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_ldxp, size, Rt2, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("ldxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldxr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldxrb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ldxrh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("ldxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_lsl_imm, sf, n, immr, imms, Rn, Rd)
{
	const uint64_t bitwidth = (sf == 0) ? 32 : 64;

	/* ALIAS: lsr_imm,ubfiz,ubfm,ubfx,uxtb,uxth */
	if ((imms != (bitwidth - 1)) && ((imms + 1) == immr)) {
		PRINTF("lsl\t%s, %s, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    bitwidth - immr);
	} else if (imms == (bitwidth - 1)) {
		PRINTF("lsr\t%s, %s, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr);
	} else if (imms < immr) {
		PRINTF("ubfiz\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    (bitwidth - immr) & (bitwidth - 1),
		    (imms + 1) & (bitwidth - 1));
	} else if (BFXPreferred(sf, 1, imms, immr)) {
		PRINTF("ubfx\t%s, %s, #%lu, #%lu\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    immr,
		    (imms - immr + 1) & (bitwidth - 1));
	} else if ((immr == 0) && (imms == 7)) {
		PRINTF("uxtb\t%s, %s\n",
		    ZREGNAME(0, Rd),
		    ZREGNAME(0, Rn));
	} else if ((immr == 0) && (imms == 15)) {
		PRINTF("uxth\t%s, %s\n",
		    ZREGNAME(0, Rd),
		    ZREGNAME(0, Rn));
	} else {
		UNDEFINED(pc, insn, "unknown");
	}
}

static void
OPFUNC_DECL(op_lsl_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: lslv */
	/* "lsl" always the preferred disassembly */
	PRINTF("lsl\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_lsr_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: lsrv */
	/* "lsr" always the preferred disassembly */
	PRINTF("lsr\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_madd, sf, Rm, Ra, Rn, Rd, UNUSED5)
{
	/* ALIAS: mul */
	if (Ra == 31) {
		PRINTF("mul\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("madd\t%s, %s, %s, %s\n",
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
		PRINTF("mneg\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("msub\t%s, %s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm),
		    ZREGNAME(sf, Ra));
	}
}

static void
OPFUNC_DECL(op_mov_bmimm, sf, n, immr, imms, Rn, Rd)
{
	if (!ValidBitMasks(sf, n, imms, immr)) {
		UNDEFINED(pc, insn, "illegal bitmasks");
		return;
	}

	/* ALIAS: orr_imm */
#if 1
	/* to distinguish from mov_iwimm */
	if ((Rn == 31) && !MoveWidePreferred(sf, n, immr, imms)) {
#else
	/* same as objdump? */
	(void)MoveWidePreferred;
	if (Rn == 31) {
#endif
		PRINTF("mov\t%s, #0x%lx\n",
		    SREGNAME(sf, Rd),
		    DecodeBitMasks(sf, n, imms, immr));
	} else {
		PRINTF("orr\t%s, %s, #0x%lx\n",
		    SREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    DecodeBitMasks(sf, n, imms, immr));
	}
}

static void
OPFUNC_DECL(op_mov_iwimm, sf, hw, imm16, Rd, UNUSED4, UNUSED5)
{
	const uint64_t mask = (sf == 0) ? 0xffffffff : 0xffffffffffffffffUL;

	if ((sf == 0) && (hw >= 2)) {
		UNDEFINED(pc, insn, "illegal size");
		return;
	}

	/* ALIAS: movn */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("mov\t%s, #0x%lx\n",
		    ZREGNAME(sf, Rd),
		    (~(ZeroExtend(16, imm16, 1) & mask)) & mask);
	} else {
		/* movn */
		const uint64_t shift = hw * 16;
		PRINTF("mov\t%s, #0x%lx\n",
		    ZREGNAME(sf, Rd),
		    ~(ZeroExtend(16, imm16, 1) << shift));
	}
}

static void
OPFUNC_DECL(op_mov_reg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: orr_reg */
	if ((Rn == 31) && (imm6 == 0)) {
		PRINTF("mov\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		shiftreg_common("orr", NULL, NULL, pc, insn,
		    sf, shift, Rm, imm6, Rn, Rd);
	}
}

static void
OPFUNC_DECL(op_mov_wimm, sf, hw, imm16, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: movz */
	if ((hw == 0) || (imm16 == 0)) {
		PRINTF("mov\t%s, #0x%lx\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		const int shift = hw * 16;
#if 0
		PRINTF("movz\t%s, #0x%lx, lsl #%d\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
#else
		/* same as objdump */
		PRINTF("mov\t%s, #0x%lx\n",
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
		PRINTF("movk\t%s, #0x%lx\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1));
	} else {
		PRINTF("movk\t%s, #0x%lx, lsl #%d\n",
		    ZREGNAME(sf, Rd),
		    ZeroExtend(16, imm16, 1), shift);
	}
}

static void
OPFUNC_DECL(op_mrs, op0, op1, CRn, CRm, op2, Rt)
{
	char buf[SYSREGNAMEBUFLEN];

	PRINTF("mrs\t%s, %s\n",
	    ZREGNAME(1, Rt),
	    RSYSREGNAME(buf, sizeof(buf), op0, op1, CRn, CRm, op2));
}

static void
OPFUNC_DECL(op_msr, op0, op1, CRn, CRm, op2, Rt)
{
	char buf[SYSREGNAMEBUFLEN];

	PRINTF("msr\t%s, %s\n",
	    WSYSREGNAME(buf, sizeof(buf), op0, op1, CRn, CRm, op2),
	    ZREGNAME(1, Rt));
}

static void
OPFUNC_DECL(op_msr_imm, op1, CRm, op2, UNUSED3, UNUSED4, UNUSED5)
{
	const char *pstatefield;

#define MSRIMM_OP(op1, op2)	(((op1) << 3) | (op2))

	switch (MSRIMM_OP(op1, op2)) {
	case MSRIMM_OP(0, 5):
		pstatefield = "spsel";
		break;
	case MSRIMM_OP(3, 6):
		pstatefield = "daifset";
		break;
	case MSRIMM_OP(3, 7):
		pstatefield = "daifclr";
		break;
	default:
		UNDEFINED(pc, insn, "illegal op1/op2");
		return;
	}

	PRINTF("msr\t%s, #0x%lx\n",
	    pstatefield, CRm);
}

static void
OPFUNC_DECL(op_mvn, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: orn */
	shiftreg_common("orn", "mvn", NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_neg, sf, shift, Rm, imm6, Rn, Rd)
{
	/* ALIAS: sub_shiftreg */
	shiftreg_common("sub", "neg", NULL, pc, insn,
	    sf, shift, Rm, imm6, Rn, Rd);
}

static void
OPFUNC_DECL(op_ngc, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: sbc */
	if (Rn == 31) {
		PRINTF("ngc\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("sbc\t%s, %s, %s\n",
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
		PRINTF("ngcs\t%s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rm));
	} else {
		PRINTF("sbcs\t%s, %s, %s\n",
		    ZREGNAME(sf, Rd),
		    ZREGNAME(sf, Rn),
		    ZREGNAME(sf, Rm));
	}
}

static void
OPFUNC_DECL(op_prfm_imm, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("prfm\t%s, [%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("prfm\t%s, [%s,#%ld]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm12, 8));
	}
}

static void
OPFUNC_DECL(op_prfm_literal, imm19, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("prfm\t%s, %lx\n",
	    PREFETCHNAME(Rt),
	    SignExtend(19, imm19, 4) + pc);
}

static void
OPFUNC_DECL(op_prfm_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	int r;

	if ((r = regoffset_option_to_r(option)) < 0) {
		UNDEFINED(pc, insn, "illegal option");
		return;
	}

	if (shift == 0) {
		PRINTF("prfm\t%s, [%s,%s%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", ",uxtw", "", "", "", ",sxtw", ",sxtx"));
	} else {
		PRINTF("prfm\t%s, [%s,%s,%s #%lu]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    ZREGNAME(r, Rm),
		    SHIFTOP8(option,
		        "", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"),
		    3);
	}
}

static void
OPFUNC_DECL(op_prfum, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("prfum\t%s, [%s]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("prfum\t%s, [%s,#%ld]\n",
		    PREFETCHNAME(Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_rbit, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("rbit\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_ret, Rn, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	if (Rn == 30)
		PRINTF("ret\n");
	else
		PRINTF("ret\t%s\n", ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_rev, sf, x, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("rev\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_rev16, sf, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("rev16\t%s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn));
}

static void
OPFUNC_DECL(op_rev32, Rn, Rd, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("rev\t%s, %s\n",
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_ror_reg, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: rorv */
	/* "ror" always the preferred disassembly */
	PRINTF("ror\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_sdiv, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("sdiv\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_smaddl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: smull */
	if (Ra == 31) {
		PRINTF("smull\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm));
	} else {
		PRINTF("smaddl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_smc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("smc\t#0x%lx\n",
	    imm16);
}

static void
OPFUNC_DECL(op_smnegl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: smsubl */
	if (Ra == 31) {
		PRINTF("smnegl\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("smsubl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_smulh, Rm, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("smulh\t%s, %s, %s\n",
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

static void
OPFUNC_DECL(op_stlr, size, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stlr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlrb, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stlrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlrh, Rn, Rt, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stlrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlxp, size, Rs, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("stlxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlxr, size, Rs, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("stlxr\t%s, [%s]\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlxrb, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stlxrb\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stlxrh, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stlxrh\t%s, [%s]\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stnp, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("stnp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stnp\t%s, %s, [%s,#%ld]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_stp_postidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("stp\t%s, %s, [%s],#%ld\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_stp_preidx, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("stp\t%s, %s, [%s,#%ld]!\n",
	    ZREGNAME(sf, Rt),
	    ZREGNAME(sf, Rt2),
	    SREGNAME(1, Rn),
	    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
}

static void
OPFUNC_DECL(op_stp_signed, sf, imm7, Rt2, Rn, Rt, UNUSED5)
{
	if (imm7 == 0) {
		PRINTF("stp\t%s, %s, [%s]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stp\t%s, %s, [%s,#%ld]\n",
		    ZREGNAME(sf, Rt),
		    ZREGNAME(sf, Rt2),
		    SREGNAME(1, Rn),
		    SignExtend(7, imm7, (sf == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_str_immpostidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("str\t%s, [%s],#%ld\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_str_immpreidx, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("str\t%s, [%s,#%ld]!\n",
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_str_immunsign, size, imm12, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("str\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("str\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, (size == 0) ? 4 : 8));
	}
}

static void
OPFUNC_DECL(op_str_reg, size, Rm, option, shift, Rn, Rt)
{
	regoffset_x_common("str", pc, insn, size, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_strb_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("strb\t%s, [%s],#%ld\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strb_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("strb\t%s, [%s,#%ld]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strb_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("strb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("strb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 1));
	}
}

static void
OPFUNC_DECL(op_strb_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	regoffset_b_common("strb", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_strh_immpostidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("strh\t%s, [%s],#%ld\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strh_immpreidx, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("strh\t%s, [%s,#%ld]!\n",
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn),
	    SignExtend(9, imm9, 1));
}

static void
OPFUNC_DECL(op_strh_immunsign, imm12, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm12 == 0) {
		PRINTF("strh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("strh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    ZeroExtend(12, imm12, 2));
	}
}

static void
OPFUNC_DECL(op_strh_reg, Rm, option, shift, Rn, Rt, UNUSED5)
{
	regoffset_h_common("strh", pc, insn, Rm, option, shift, Rn, Rt);
}

static void
OPFUNC_DECL(op_sttr, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("sttr\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttr\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_sttrb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("sttrb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttrb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_sttrh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("sttrh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sttrh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(12, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_stur, size, imm9, Rn, Rt, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("stur\t%s, [%s]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("stur\t%s, [%s,#%ld]\n",
		    ZREGNAME(size, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_sturb, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("sturb\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sturb\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_sturh, imm9, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	if (imm9 == 0) {
		PRINTF("sturh\t%s, [%s]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn));
	} else {
		PRINTF("sturh\t%s, [%s,#%ld]\n",
		    ZREGNAME(0, Rt),
		    SREGNAME(1, Rn),
		    SignExtend(9, imm9, 1));
	}
}

static void
OPFUNC_DECL(op_stxp, size, Rs, Rt2, Rn, Rt, UNUSED5)
{
	PRINTF("stxp\t%s, %s, [%s]\n",
	    ZREGNAME(size, Rt),
	    ZREGNAME(size, Rt2),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stxr, size, Rs, Rn, Rt, UNUSED4, UNUSED5)
{
	PRINTF("stxr\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(size, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stxrb, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stxrb\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_stxrh, Rs, Rn, Rt, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("stxrh\t%s, %s, [%s]\n",
	    ZREGNAME(0, Rs),
	    ZREGNAME(0, Rt),
	    SREGNAME(1, Rn));
}

static void
OPFUNC_DECL(op_sub_extreg, sf, Rm, option, imm3, Rn, Rd)
{
	extendreg_common("sub", NULL,
	    pc, insn, sf, Rm, option, imm3, Rn, Rd);
}

static void
OPFUNC_DECL(op_sub_imm, sf, shift, imm12, Rn, Rd, UNUSED5)
{
	if (shift & 2) {
		UNDEFINED(pc, insn, "illegal shift");
		return;
	}

	PRINTF("sub\t%s, %s, #0x%lx%s\n",
	    SREGNAME(sf, Rd),
	    SREGNAME(sf, Rn),
	    ZeroExtend(12, imm12, 1),
	    SHIFTOP2(shift, "", ", lsl #12"));
}

static void
OPFUNC_DECL(op_svc, imm16, UNUSED1, UNUSED2, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("svc\t#0x%lx\n",
	    imm16);
}

static void
OPFUNC_DECL(op_sysl, op1, CRn, CRm, op2, Rt, UNUSED5)
{
	PRINTF("sysl\t%s, #%lu, %s, %s, #%lu\n",
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

	PRINTF("tbnz\t%s, #%lu, %lx\n",
	    ZREGNAME(b5, Rt),
	    bit,
	    SignExtend(14, imm14, 4) + pc);
}

static void
OPFUNC_DECL(op_tbz, b5, b40, imm14, Rt, UNUSED4, UNUSED5)
{
	uint64_t bit = (b5 << 5) + b40;

	PRINTF("tbz\t%s, #%lu, %lx\n",
	    ZREGNAME(b5, Rt),
	    bit,
	    SignExtend(14, imm14, 4) + pc);
}

static void
OPFUNC_DECL(op_udiv, sf, Rm, Rn, Rd, UNUSED4, UNUSED5)
{
	PRINTF("udiv\t%s, %s, %s\n",
	    ZREGNAME(sf, Rd),
	    ZREGNAME(sf, Rn),
	    ZREGNAME(sf, Rm));
}

static void
OPFUNC_DECL(op_umaddl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: umull */
	if (Ra == 31) {
		PRINTF("umull\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm));
	} else {
		PRINTF("umaddl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(0, Rn),
		    ZREGNAME(0, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_umnegl, Rm, Ra, Rn, Rd, UNUSED4, UNUSED5)
{
	/* ALIAS: umsubl */
	if (Ra == 31) {
		PRINTF("umnegl\t%s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm));
	} else {
		PRINTF("umsubl\t%s, %s, %s, %s\n",
		    ZREGNAME(1, Rd),
		    ZREGNAME(1, Rn),
		    ZREGNAME(1, Rm),
		    ZREGNAME(1, Ra));
	}
}

static void
OPFUNC_DECL(op_umulh, Rm, Rn, Rd, UNUSED3, UNUSED4, UNUSED5)
{
	PRINTF("umulh\t%s, %s, %s\n",
	    ZREGNAME(1, Rd),
	    ZREGNAME(1, Rn),
	    ZREGNAME(1, Rm));
}

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
			if (insn_tables[i].bitinfo[j].width == 0)
				break;
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
			printf_buffer += ret;
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


	/* fetch instruction */
	insn = *(uint32_t *)insnp;

	/* print address/insn */
	PRINTF("%12lx:\t%08x\t", loc, insn);

	/* print insn */
	disasm_insn(loc, insn);


	printf_buffer = NULL;
	printf_size = 0;

	return sizeof(uint32_t);
}
