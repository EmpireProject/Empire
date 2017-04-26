#
# Include generated dependency files.
#
XAR_SRCS := xar.c
XAR_SRCS := $(patsubst %, src/%, $(XAR_SRCS))
-include $(XAR_SRCS:%.c=%.d)

src_all : src/xar src/ixar

src_install : src/ixar
	/usr/bin/install -c -d $(DESTDIR)$(BINDIR)
	/usr/bin/install -c -m 0755 $< $(DESTDIR)$(BINDIR)/xar
	/usr/bin/install -c -d $(DESTDIR)$(MANDIR)/man1
	/usr/bin/install -c -m 0644 src/xar.1 $(DESTDIR)$(MANDIR)/man1

src_uninstall :
	rm -f $(DESTDIR)/$(BINDIR)/xar
	rm -f $(DESTDIR)/$(MANDIR)/man1/xar.1

src_clean :
	rm -f src/xar
	rm -f src/ixar
	rm -f $(XAR_SRCS:%.c=%.o)
	rm -f $(XAR_SRCS:%.c=%.d)

src_distclean :


ifeq (yes, yes)
LIBRXAR := $(LIBRXAR_S)
endif
ifeq (yes, yes)
LIBRXAR := $(LIBXAR_A)
endif

# xar links against librxar, so that it can be run without first installing
# libxar.
src/% : src/%.o $(LIBRXAR)
	@mkdir -p $(@D)
ifneq ($(words "" -Wl,-rpath,), 1)
	$(CC) $(CFLAGS) -o $@ $< -Wl,-rpath,/home/bneg/Code/Empire/2.0_beta/setup/xar-1.5.2/lib $(LDFLAGS) $(LIBRXAR) -lz -lcrypto  -lxml2
else
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBRXAR) -lz -lcrypto  -lxml2
endif

ifeq (yes, yes)
LIBXAR := $(LIBXAR_A)
endif
ifeq (yes, yes)
LIBXAR := $(LIBXAR_S)
endif

# ixar is the version of the xar binary that gets installed.
src/i% : src/%.o $(LIBXAR)
	@mkdir -p $(@D)
ifneq ($(words "" -Wl,-rpath,), 1)
	$(CC) $(CFLAGS) -o $@ $< -Wl,-rpath,$(LIBDIR) $(LDFLAGS) $(LIBXAR) -lz -lcrypto  -lxml2
else
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBXAR) -lz -lcrypto  -lxml2
endif

src/%.o : src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@
	@$(SHELL) -ec "$(CC) -MM $(CPPFLAGS) $< | sed \"s/\($(subst /,\/,$(notdir $(basename $@)))\)\.o\([ :]*\)/$(subst /,\/,$(strip $(dir $@)))\1.o \2/g\" > $(@:%.o=%.d)"
