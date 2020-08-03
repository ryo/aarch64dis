#!/usr/local/bin/perl

use strict;
use warnings;


while (<>) {
	chop;

	s,^#include "disasm.h",#include <arch/aarch64/aarch64/disasm.h>,;

	if (m,^#include "disasm_sysreg.h",) {
		open(H, "disasm_sysreg.h");
		print <H>;
		close(H);
		next;
	}
	if (m,^#include "disasm_table.h",) {
		open(H, "disasm_table.h");
		print <H>;
		close(H);
		next;
	}

	print $_, "\n";
}
