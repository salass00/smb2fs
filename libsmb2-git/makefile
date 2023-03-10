CC     = ppc-amigaos-gcc
AR     = ppc-amigaos-ar
RANLIB = ppc-amigaos-ranlib
STRIP  = ppc-amigaos-strip

OPTIMIZE = -O2
DEBUG    = -gstabs
WARNINGS = -Wall -Werror -Wwrite-strings
INCLUDES = -I. -I./include -I./include/smb2
DEFINES  = -DHAVE_CONFIG_H "-D_U_=__attribute__((unused))"

CFLAGS  = $(OPTIMIZE) $(DEBUG) $(WARNINGS) $(INCLUDES) $(DEFINES)

STRIPFLAGS = -R.comment --strip-unneeded-rel-relocs

SRCS = aes.c aes128ccm.c alloc.c dcerpc.c dcerpc-lsa.c dcerpc-srvsvc.c \
       errors.c init.c hmac.c hmac-md5.c krb5-wrapper.c libsmb2.c md4c.c \
       md5.c ntlmssp.c pdu.c sha1.c sha224-256.c sha384-512.c \
       smb2-cmd-close.c smb2-cmd-create.c smb2-cmd-echo.c smb2-cmd-error.c \
       smb2-cmd-flush.c smb2-cmd-ioctl.c smb2-cmd-logoff.c \
       smb2-cmd-negotiate.c smb2-cmd-query-directory.c smb2-cmd-query-info.c \
       smb2-cmd-read.c smb2-cmd-session-setup.c smb2-cmd-set-info.c \
       smb2-cmd-tree-connect.c smb2-cmd-tree-disconnect.c smb2-cmd-write.c \
       smb2-data-file-info.c smb2-data-filesystem-info.c \
       smb2-data-security-descriptor.c smb2-data-reparse-point.c \
       smb2-share-enum.c smb3-seal.c smb2-signing.c socket.c sync.c \
       timestamps.c unicode.c usha.c compat.c

OBJS = $(addprefix obj/,$(SRCS:.c=.o))

EXAMPLES = smb2-cat-async smb2-cat-sync \
           smb2-statvfs-sync \
           smb2-ls-async  smb2-ls-sync  \
           smb2-put-async smb2-put-sync

.PHONY: all
all: libsmb2.a

obj/%.o: lib/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -c -o $@ $<

libsmb2.a: $(OBJS)
	$(AR) -crv $@ $^
	$(RANLIB) $@

.PHONY: build-examples
build-examples: $(addprefix examples/,$(EXAMPLES))

examples/smb2-cat-async: examples/smb2-cat-async.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-cat-sync: examples/smb2-cat-sync.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-statvfs-sync: examples/smb2-statvfs-sync.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-ls-async: examples/smb2-ls-async.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-ls-sync: examples/smb2-ls-sync.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-put-async: examples/smb2-put-async.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

examples/smb2-put-sync: examples/smb2-put-sync.c libsmb2.a
	$(CC) $(CFLAGS) -o $@.debug $^
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

.PHONY: clean
clean:
	rm -rf libsmb2.a obj
	rm -rf $(addprefix examples/,$(EXAMPLES)) examples/*.debug

