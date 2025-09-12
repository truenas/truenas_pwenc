CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -fPIC -O2 -g
LDFLAGS = -shared
LIBS = -lssl -lcrypto -lbsd
PREFIX = /usr/local

# Library versioning
MAJOR = 1
MINOR = 0
PATCH = 0
VERSION = $(MAJOR).$(MINOR).$(PATCH)

SRCDIR = src/pwenc
OBJDIR = obj
LIBDIR = lib

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
SONAME = libtruenas_pwenc.so.$(MAJOR)
LIBRARY = $(LIBDIR)/libtruenas_pwenc.so.$(VERSION)
SOFILE = $(LIBDIR)/$(SONAME)
LINKNAME = $(LIBDIR)/libtruenas_pwenc.so

.PHONY: all library clean install

all: library

library: $(LIBRARY) $(SOFILE) $(LINKNAME)

$(LIBRARY): $(OBJECTS) | $(LIBDIR)
	$(CC) $(LDFLAGS) -Wl,-soname,$(SONAME) -o $@ $^ $(LIBS)

$(SOFILE): $(LIBRARY) | $(LIBDIR)
	cd $(LIBDIR) && ln -sf libtruenas_pwenc.so.$(VERSION) $(SONAME)

$(LINKNAME): $(SOFILE) | $(LIBDIR)
	cd $(LIBDIR) && ln -sf $(SONAME) libtruenas_pwenc.so

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(LIBDIR):
	mkdir -p $(LIBDIR)

clean:
	rm -rf $(OBJDIR) $(LIBDIR)

install: library
	install -d $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include
	install $(LIBRARY) $(DESTDIR)$(PREFIX)/lib/
	ln -sf libtruenas_pwenc.so.$(VERSION) $(DESTDIR)$(PREFIX)/lib/$(SONAME)
	ln -sf $(SONAME) $(DESTDIR)$(PREFIX)/lib/libtruenas_pwenc.so
	install -m644 $(SRCDIR)/truenas_pwenc.h $(DESTDIR)$(PREFIX)/include/