#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>

#include "disasm.h"


/*
 * for test
 */
char *printf_buffer = NULL;
size_t printf_size;

static void
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
}

static void
test_printaddr(uintptr_t loc)
{
#if 0
	test_printf("%lx <0x%lx>", loc, loc);
#else
	test_printf("%lx", loc);
#endif
}

static uint32_t
test_readword(uintptr_t loc)
{
	uint32_t *p;

	p = (uint32_t *)loc;
	return *p;
}

disasm_interface_t test_di = {
	.di_readword = test_readword,
	.di_printaddr = test_printaddr,
	.di_printf = test_printf
};

static int
strdisasm(uint64_t loc, uint32_t insn, char *buf, size_t bufsize)
{
	printf_buffer = buf;
	printf_size = bufsize;

#if 1
	/* print address/insn */
	test_printf("%12lx:\t%08x\t", loc, insn);
#else
	test_di.di_printaddr(loc);
	test_di.di_printf(":\t%08x\t", insn);
#endif

	/* print insn */
	disasm_insn(&test_di, loc, insn);


	printf_buffer = NULL;
	printf_size = 0;

	return sizeof(uint32_t);
}




static int __unused
chop(char *p)
{
	int ch;

	if (*p == '\0')
		return -1;

	while (*p++)
		;

	ch = p[-2] & 0xff;
	p[-2] = '\0';

	return ch;
}

static int
chomp(char *p)
{
	if (*p == '\0')
		return -1;

	while (*p++)
		;

	if (p[-2] == '\n') {
		p[-2] = '\0';
		return '\n';
	}
	return -1;
}

static bool
ishex(char c)
{
	if (isdigit((int)c) ||
	     (('a' <= c) && (c <= 'f')) ||
	     (('A' <= c) && (c <= 'F')))
		return true;
	return false;
}

static char *
fetch_hex(char *p, uint64_t *hex)
{
	char tmpbuf[1024];
	char *d;

	d = tmpbuf;
	while (ishex(*p)) {
		*d++ = *p++;
	}
	if (d == tmpbuf)
		return NULL;

	*d++ = '\0';

	*hex = strtoul(tmpbuf, NULL, 16);
	return p;
}

static inline void
strfuzzy(char *str)
{
	char c;
	char *p;

	p = str;

	for (;;) {
		c = *str;
		if (c == '\0') {
			*p++ = '\0';
			return;
		}
		if (c == ' ' || c == '\t') {
			*str++ = ' ';
			while (*str == ' ' || *str == '\t')
				str++;
		} else if (c == '#') {
			*str++ = ';';
		} else {
			*p++ = c;
			str++;
		}
	}
}


static int
strfuzzycmp(const char *s1, const char *s2)
{
	int result;
	char *p1 = strdup(s1);
	char *p2 = strdup(s2);
	char *p;

	strfuzzy(p1);
	strfuzzy(p2);

	p = strstr(p2, ".insn");
	if (p != NULL)
		p[4] = 't';

	result = strcmp(p1, p2);
	free(p1);
	free(p2);
	return result;
}

static bool
parse_disasm(char *p)
{
	uint64_t loc;
	uint64_t insn;
	char *origline;
	char origbuf[1024];
	char origbuf_cmp[1024];
	char asmbuf[1024];
	char asmbuf_cmp[1024];

	origline = p;

	p = fetch_hex(p, &loc);
	if (p == NULL) {
		printf("ERROR: fetch addr: \"%s\"\n", origline);
		return false;
	}

	if (*p != ':') {
		printf("ERROR: skip colon: \"%s\"\n", origline);
		return false;
	}
	p++;

	if (*p != '\t') {
		printf("ERROR: skip tab: \"%s\"\n", origline);
		return false;
	}
	p++;

	p = fetch_hex(p, &insn);
	if (p == NULL) {
		printf("ERROR: fetch insn: \"%s\"\n", origline);
		return false;
	}

	if (*p != ' ') {
		printf("ERROR: skip space: \"%s\"\n", origline);
		return false;
	}
	p++;

	if (*p != '\t') {
		printf("ERROR: skip tab: \"%s\"\n", origline);
		return false;
	}
	p++;

	origline = p;

	strdisasm(loc, insn, asmbuf, sizeof(asmbuf));
	snprintf(origbuf, sizeof(origbuf), "%12llx:	%08x	%s", (unsigned long long)loc, (uint32_t)insn, origline);
	strncpy(asmbuf_cmp, asmbuf, sizeof(asmbuf_cmp));
	strncpy(origbuf_cmp, origbuf, sizeof(origbuf_cmp));

	/* cut " <symbol...>" */
	p = strstr(origbuf_cmp, " <");
	if (p != NULL)
		*p = '\0';

	/*
	 * cut "\t# comment"
	 */
	chomp(asmbuf_cmp);
	p = asmbuf_cmp;
	/* XXX: cannot remove comment from opcode only line. e.g. "nop	#comment" */
	for (int i = 0; i < 3; i++) {
		p = index(p, '\t');
		if ((i != 2) && (p == NULL)) {
			printf("ERROR: not found %dth tab after opcode: \"%s\"\n", i, origline);
			return false;
		}
		if (p != NULL)
			p += 1;
	}
	if (p != NULL) {
		p = strstr(p + 1, "\t#");
		if (p != NULL) {
			*p = '\0';
		}
	}

	/*
	 * cut "\t// #imm" from original
	 */
	p = strstr(origbuf_cmp, "//");
	if (p != NULL) {
		while ((p[-1] == '\t') || (p[-1] == ' '))
			p--;
		*p = '\0';
	}

	/*
	 * cut "; xxx" from original
	 */
	p = strstr(origbuf_cmp, " ; ");
	if (p != NULL) {
		*p = '\0';
	}


	if (strfuzzycmp(origbuf_cmp, asmbuf_cmp) == 0) {
#if 1
		printf("%s\n", origbuf);
		printf("%s\n", asmbuf);
#endif
	} else {
		printf("binutils:	%s\n", origbuf);
		printf("MYdisasm:	%s\n", asmbuf);
	}

	return true;
}


int
main(int argc, char *argv[])
{
	char buf[1024];
	char *p, *q, c;

	while ((p = fgets(buf, sizeof(buf), stdin)) != NULL) {
		bool disasmline = false;
		chomp(p);

		while (*p == ' ')
			p++;

		c = *p;
		if (ishex(c)) {
			q = p;
			while (ishex(*q))
				q++;
			if (*q == ':') {
				disasmline = true;
			}
		}

		if (disasmline)
			disasmline = parse_disasm(p);

		if (!disasmline)
			printf("#	%s\n", buf);

	}
}
