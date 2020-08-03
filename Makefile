
CC	?= cc
CXX	?= g++
DBG	= -O3
#DBG	+= -g
CFLAGS	= ${DBG} -pipe -I/usr/local/include
CFLAGS +=-Wall \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wpointer-arith \
	-Wno-sign-compare \
	-Wa,--fatal-warnings \
	-Wreturn-type \
	-Wswitch \
	-Wshadow \
	-Wcast-qual \
	-Wwrite-strings \
	-Wextra \
	-Wno-unused-parameter \
	-Wno-sign-compare \
	-Wold-style-definition \
	-Wsign-compare \
	-Wformat=2 \
	-Wno-format-nonliteral \
	-Wno-format-zero-length \
	-Werror
CFLAGS +=-DDISASM_WITH_COMMENT

CXXAGS	= ${CFLAGS:S/-Wno-traditional//}
LD	= ${CC}
MKDEP	= mkdep
PERL	= perl
LIBS	= -L/usr/local/lib

PROGRAM	= disasm_test
SRCS	= test.c disasm.c
OBJS	= $(SRCS)
OBJS	:= $(OBJS:.c=.o)
OBJS	:= $(OBJS:.cc=.o)
OBJS	:= $(OBJS:.cpp=.o)
OBJS	:= $(OBJS:.cxx=.o)

.c.o:
	$(CC) -c $(CFLAGS) $<

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $<


$(PROGRAM): $(OBJS)
	$(LD) $(OBJS) -o $(PROGRAM) $(LIBS)

mkheaders:
	$(PERL) table_generator asm.defs > disasm_table.h
	$(PERL) sysreg_gen > disasm_sysreg.h

depend:
	$(MKDEP) $(SRCS)

clean:
	-rm -f *.o $(PROGRAM) *.tmp

cleandir: clean
	-rm -f .depend

test_netbsd:
	aarch64--netbsd-objdump -d /usr/src/sys/arch/evbarm/compile/GENERIC64/netbsd | ./disasm_test | less -r

diff_netbsd:
	aarch64--netbsd-objdump -d /usr/src/sys/arch/evbarm/compile/GENERIC64/netbsd | ./disasm_test | egrep '^(binutil|MYdisasm)' > netbsd.tmp
	grep -v 'binutil.*\.word' netbsd.tmp | less -r -p 'binutil.*'

test_init:
	aarch64--netbsd-objdump -d /usr/src/work.evbarm64-el/tree/sbin/init | ./disasm_test | less -r

test_libc:
	aarch64--netbsd-objdump -d /usr/src/work.evbarm64-el/obj/lib/libc/libc.a | ./disasm_test | less -r

test_bin:
	aarch64--netbsd-gcc -msign-return-address=all -c bin.S
	aarch64--netbsd-strip bin.o
	aarch64--netbsd-objdump -Dr bin.o | ./disasm_test | less -r

diff_bin:
	aarch64--netbsd-gcc -msign-return-address=all -c bin.S
	aarch64--netbsd-objdump -D bin.o | ./disasm_test | egrep '^(binutil|MYdisasm)' > bin.tmp
	grep -v 'binutil.*\.word' bin.tmp | less -r -p 'binutil.*'

install:
	perl local2netbsd.pl disasm.c > /usr/src/sys/arch/aarch64/aarch64/disasm.c
