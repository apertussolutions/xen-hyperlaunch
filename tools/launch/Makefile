#
# tools/launch/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

ifeq ($(CONFIG_Linux),y)
PROGS += lcm-tool
endif

LCM_TOOL_OBJS = lcm-tool.o
LCM_TOOL_LIBS = -lyajl

.PHONY: all
all: $(PROGS)

CFLAGS += $(CFLAGS_xeninclude)

lcm-tool: $(LCM_TOOL_OBJS)
	$(CC) $(CFLAGS_xeninclude) $(LDFLAGS) -o $@ $(LCM_TOOL_OBJS) $(LCM_TOOL_LIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: all
ifeq ($(CONFIG_Linux),y)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) lcm-tool $(DESTDIR)$(LIBEXEC_BIN)
endif

.PHONY: uninstall
uninstall:
ifeq ($(CONFIG_Linux),y)
	rm -f $(DESTDIR)$(LIBEXEC_BIN)/lcm-tool
endif

.PHONY: clean
clean:
	$(RM) -f *.o $(PROGS) $(DEPS_RM)

distclean: clean
