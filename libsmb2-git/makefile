CC     = ppc-amigaos-gcc
AR     = ppc-amigaos-ar
RANLIB = ppc-amigaos-ranlib
STRIP  = ppc-amigaos-strip

OPTIMIZE = -O2
DEBUG    = -gstabs
WARNINGS = -Wall -Werror -Wwrite-strings
INCLUDES = -I. -I./include -I./include/smb2 -I./include/amigaos4
DEFINES  = -DHAVE_CONFIG_H "-D_U_=__attribute__((unused))" -DHAVE_ADDRINFO -DNEED_POLL -DNEED_GETADDRINFO -DNEED_FREEADDRINFO -DNEED_GETLOGIN_R

CFLAGS  = $(OPTIMIZE) $(DEBUG) $(WARNINGS) $(INCLUDES) $(DEFINES)

STRIPFLAGS = -R.comment --strip-unneeded-rel-relocs

SRCS = aes.c aes_reference.c aes128ccm.c alloc.c asn1-ber.c dcerpc.c \
       dcerpc-lsa.c dcerpc-srvsvc.c errors.c init.c hmac.c hmac-md5.c \
       krb5-wrapper.c libsmb2.c md4c.c md5.c ntlmssp.c pdu.c sha1.c \
       sha224-256.c sha384-512.c smb2-cmd-close.c smb2-cmd-create.c \
       smb2-cmd-echo.c smb2-cmd-error.c smb2-cmd-flush.c smb2-cmd-ioctl.c \
       smb2-cmd-lock.c smb2-cmd-logoff.c smb2-cmd-negotiate.c \
       smb2-cmd-notify-change.c smb2-cmd-oplock-break.c \
       smb2-cmd-query-directory.c smb2-cmd-query-info.c smb2-cmd-read.c \
       smb2-cmd-session-setup.c smb2-cmd-set-info.c smb2-cmd-tree-connect.c \
       smb2-cmd-tree-disconnect.c smb2-cmd-write.c smb2-data-file-info.c \
       smb2-data-filesystem-info.c smb2-data-security-descriptor.c \
       smb2-data-reparse-point.c smb2-share-enum.c smb3-seal.c \
       smb2-signing.c socket.c spnego-wrapper.c sync.c timestamps.c \
       unicode.c usha.c compat.c

OBJS = $(addprefix obj/,$(SRCS:.c=.o))
DEPS = $(OBJS:.o=.d)

.PHONY: all
all: bin/libsmb2.a

-include $(DEPS)

obj/%.o: lib/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(CFLAGS) $<
	$(CC) $(CFLAGS) -c -o $@ $<

bin/libsmb2.a: $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) -crv $@ $^
	$(RANLIB) $@

.PHONY: clean
clean:
	rm -rf bin obj

