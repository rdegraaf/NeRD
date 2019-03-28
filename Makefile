CC=gcc
CXX=g++
RM=rm -f

CCFLAGS=-Wall -Wextra -std=c99 -pedantic -g -O2 -I.
CXXFLAGS=-Wall -Wextra -ansi -pedantic -g -O2 -DBROKEN_FEXECVE \
	-DNO_NF_STOP

nerd_OBJS=nerd.o IPQ.o Signals.o spc_sanitize.o logmsg.o Logmsg.o util.o \
	drop_priv.o dns.o DnsServerRecord.o
nerd_LDFLAGS=
nerd_LIBS=-lipq /usr/lib/libresolv.a

echod_OBJS=echod.o
echod_LDFLAGS=
echod_LIBS=

.PHONY: all debug clean distclean install install-rh depend doc

all: nerd echod

debug:
	${MAKE} CXXFLAGS="${CXXFLAGS} -DDEBUG" CCFLAGS="${CCFLAGS} -DDEBUG"

nerd: ${nerd_OBJS}
	${CXX} -o $@ $^ ${LDFLAGS} ${nerd_LDFLAGS} ${nerd_LIBS}

echod: ${echod_OBJS}
	${CC} -o $@ $^ ${LDFLAGS} ${echod_LDFLAGS} ${echod_LIBS}

%.o: %.c
	${CC} -c ${CCFLAGS} $<

%.o: %.cpp
	${CXX} -c ${CXXFLAGS} $<

clean:
	${RM} a.out *.o *~

distclean: clean
	${RM} nerd echod .depend
	${RM} -r doc

doc:	
	doxygen Doxyfile

install: nerd 
	install -D -g root -o root -m 0750 nerd /usr/local/sbin/nerd
	install -D -g root -o root -m 0644 nerd.h /usr/local/include/nerd.h
	install -g root -o root -m 1777 -d /var/nerd/servers/
	install -g root -o root -m 0755 -d /usr/local/share/doc/nerd-0.3.1/html
	install -g root -o root -m 0644 README /usr/local/share/doc/nerd-0.3.1/
	if [ -d doc/html ]; then install -g root -o root -m 0644 doc/html/* /usr/local/share/doc/nerd-0.3.1/html/; fi

install-rh: install
	install -g root -o root -m 0755 nerd.sh /etc/init.d/nerd
	install -g root -o root -m 0644 nerd.conf /etc/sysconfig/nerd

depend:
	${CC} -MM *.c *.cpp >.depend

# dependencies
-include .depend

