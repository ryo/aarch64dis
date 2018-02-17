#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

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

static void
parse_disasm(char *p)
{
	uint64_t loc;
	uint32_t insn;
	char *origline;
	char asmbuf[1024];

	loc = strtol(p + 3, NULL, 16);
	insn = strtol(p + 14, NULL, 16);
	origline = p + 24;

	disasm(loc, &insn, asmbuf, sizeof(asmbuf));

	printf("%lx:	%08x	%s\n", loc, insn, origline);
	printf("%s", asmbuf);
	printf("\n");
}

int
main(int argc, char *argv[])
{
	char buf[1024];
	char *p;

	while ((p = fgets(buf, sizeof(buf), stdin)) != NULL) {
		chomp(p);

		if ((strncmp(p, "   ", 3) == 0) &&
		    (p[12] == ':') &&
		    (p[13] == '\t') &&
		    (p[22] == ' ') &&
		    (p[23] == '\t')) {

			parse_disasm(p);
		} else {
			printf("%s\n", buf);
		}
	}
}
