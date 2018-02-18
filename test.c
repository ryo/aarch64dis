#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>

#include "disasm.h"

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
	if (isdigit(c) ||
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

static bool
parse_disasm(char *p)
{
	uint64_t loc;
	uint64_t insn;
	size_t len;
	char *origline;
	char origbuf[1024];
	char asmbuf[1024];

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

	disasm(loc, &insn, asmbuf, sizeof(asmbuf));

	snprintf(origbuf, sizeof(origbuf), "%12lx:	%08x	%s", loc, (uint32_t)insn, origline);

	len = strlen(asmbuf) - 1;
	if (strncmp(origbuf, asmbuf, len) == 0) {
		printf("%s\n", origbuf);
		printf("%s\n", asmbuf);
	} else {
		printf("ORIG	%s\n", origbuf);
		printf("ERR?	%s\n", asmbuf);
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
