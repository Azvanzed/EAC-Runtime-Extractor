CC := x86_64-w64-mingw32-gcc
CFLAGS := -Wall -Werror -std=c11 -shared -DBUILD_DLL -msse4.2
SRCDIR := src
OBJDIR := obj
BINDIR := bin
SOURCES := $(shell find $(SRCDIR) -type f -name '*.c')
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET := $(BINDIR)/eac_hook.dll
LDFLAGS := -Wl,--out-implib,$(BINDIR)/eac_hook.a

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BINDIR)
	@$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	-@rm -rf $(OBJDIR) $(BINDIR)

.PHONY: all clean
