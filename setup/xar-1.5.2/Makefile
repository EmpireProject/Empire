# Clear out all vpaths, then set just one (default vpath) for the main build
# directory.
vpath
vpath % .

# Clear the default suffixes, so that built-in rules are not used.
.SUFFIXES :

#
# Standard definitions.
#

SHELL := /bin/sh
CC := gcc
LD := /usr/bin/ld
AR := /usr/bin/ar
RANLIB := /usr/bin/ranlib
INSTALL := /usr/bin/install -c
AUTOCONF := 

#
# Build parameters.
#

CPPFLAGS :=  -D_GNU_SOURCE -I/usr/include/libxml2
CFLAGS := -Wall -g 
A_CFLAGS := $(CFLAGS) 
S_CFLAGS := $(CFLAGS) -fPIC -DPIC
ifeq (macho, elf)
S_CFLAGS += -dynamic
endif
LDFLAGS :=  

prefix := /usr/local
bindir := /usr/local/bin
datadir := /usr/local/share
libdir := /usr/local/lib
includedir := /usr/local/include
mandir := /usr/local/man

PREFIX := $(prefix)
BINDIR := $(bindir)
DATADIR := $(datadir)
LIBDIR := $(libdir)
INCLUDEDIR := $(includedir)
MANDIR := $(mandir)

dir_names := lib src

all : $(dir_names:%=%_all)

install : $(dir_names:%=%_install)

uninstall : $(dir_names:%=%_uninstall)

clean : $(dir_names:%=%_clean)

distclean : clean $(dir_names:%=%_distclean)
	rm -f config.log
	rm -f config.status
	rm -f cfghdrs.stamp
	rm -f cfgoutputs.stamp
	rm -f configure.lineno
	rm -f cfghdrs.stamp include/config.h
	rm -f cfgoutputs.stamp Makefile include/xar.h lib/Makefile.inc lib/libxar.la.in src/Makefile.inc xar.spec
	rm -rf autom4te.cache

relclean : distclean
	rm -f configure

# Include Makefile.inc files in subdirectories.
include $(dir_names:%=%/Makefile.inc)

#
# Re-configuration rules.
#
ifeq (0, 1)
configure : configure.ac
	cd ./ && $(AUTOCONF)

config.status : configure
	./config.status --recheck

# cfghdrs rules.
cfghdrs.stamp.in : configure.ac
	echo stamp > cfghdrs.stamp.in

$(patsubst %, %.in, cfghdrs.stamp include/config.h) : config.status

cfghdrs.stamp : $(patsubst %, %.in, cfghdrs.stamp include/config.h)
	./config.status
	echo stamp > $@

$(filter-out cfghdrs.stamp, cfghdrs.stamp include/config.h) : cfghdrs.stamp

# cfgoutputs rules.
cfgoutputs.stamp.in : configure.ac
	echo stamp > cfgoutputs.stamp.in

$(patsubst %, %.in, cfgoutputs.stamp Makefile include/xar.h lib/Makefile.inc lib/libxar.la.in src/Makefile.inc xar.spec) : config.status

cfgoutputs.stamp : $(patsubst %, %.in, cfgoutputs.stamp Makefile include/xar.h lib/Makefile.inc lib/libxar.la.in src/Makefile.inc xar.spec)
	./config.status

$(filter-out \
	cfgoutputs.stamp, \
	$(patsubst %, %, cfgoutputs.stamp Makefile include/xar.h lib/Makefile.inc lib/libxar.la.in src/Makefile.inc xar.spec)) : cfgoutputs.stamp
endif
