CC    = ppc-amigaos-gcc
STRIP = ppc-amigaos-strip

TARGET  = smb2-handler
VERSION = 53

LIBSMB2DIR = libsmb2-git

OPTIMIZE = -O2
DEBUG    = -gstabs
INCLUDES = -I. -I./src -I./$(LIBSMB2DIR)/include
DEFINES  = 
WARNINGS = -Wall -Wwrite-strings -Werror

CFLAGS  = $(OPTIMIZE) $(DEBUG) $(INCLUDES) $(DEFINES) $(WARNINGS)
LDFLAGS = -static
LIBS    = 

STRIPFLAGS = -R.comment --strip-unneeded-rel-relocs

SRCS = start.c main.c error-req.c time.c bsdsocket-stubs.c marshalling.c \
       reaction/password-req.c amigaos4/reconnect-req.c

OBJS = $(addprefix obj/,$(SRCS:.c=.o))
DEPS = $(OBJS:.o=.d)

.PHONY: all
all: bin/$(TARGET)

-include $(DEPS)

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(CFLAGS) $<
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: build-libsmb2
build-libsmb2:
	$(MAKE) -C $(LIBSMB2DIR) bin/libsmb2.a

$(LIBSMB2DIR)/bin/libsmb2.a: build-libsmb2
	@true

bin/$(TARGET): $(OBJS) $(LIBSMB2DIR)/bin/libsmb2.a
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

.PHONY: clean
clean:
	$(MAKE) -C $(LIBSMB2DIR) clean
	rm -rf bin obj

.PHONY: revision
revision:
	bumprev -e is $(VERSION) $(TARGET)

