# ifnsupdate — build, test, and install
#
# Common usage:
#   make              # build binary
#   make test
#   sudo make install # binary + example config + systemd unit

PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
SYSCONFDIR  ?= /etc/ifnsupdate
UNITDIR     ?= /etc/systemd/system

# DESTDIR is prepended for staged installs (packaging)
DESTDIR     ?=

BINARY      := ifnsupdate
OUTDIR      ?= bin
OUT         := $(OUTDIR)/$(BINARY)
GO          ?= go
GOFLAGS     ?= -trimpath
LDFLAGS     ?= -s -w

.PHONY: all build test vet clean install uninstall help

all: build

build:
	mkdir -p $(OUTDIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(OUT) .

test:
	$(GO) test $(GOFLAGS) ./...

vet:
	$(GO) vet $(GOFLAGS) ./...

clean:
	rm -rf $(OUTDIR)
	rm -f $(BINARY) # legacy path (pre-bin/ layout)

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(OUT) $(DESTDIR)$(BINDIR)/$(BINARY)
	install -d $(DESTDIR)$(SYSCONFDIR)
	# Never overwrite a live config (may contain TSIG secrets)
	if [ ! -e $(DESTDIR)$(SYSCONFDIR)/config.yaml ]; then \
		install -m 600 config.yaml.example $(DESTDIR)$(SYSCONFDIR)/config.yaml; \
	fi
	install -m 644 config.yaml.example $(DESTDIR)$(SYSCONFDIR)/config.yaml.example
	install -d $(DESTDIR)$(UNITDIR)
	install -m 644 ifnsupdate.service $(DESTDIR)$(UNITDIR)/ifnsupdate.service
	@echo
	@echo "Installed $(BINARY) to $(DESTDIR)$(BINDIR)/$(BINARY)"
	@echo "Config:  $(DESTDIR)$(SYSCONFDIR)/config.yaml (edit before enabling)"
	@echo "Unit:    $(DESTDIR)$(UNITDIR)/ifnsupdate.service"
	@echo
	@echo "Next steps:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now ifnsupdate"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	rm -f $(DESTDIR)$(UNITDIR)/ifnsupdate.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/config.yaml.example
	@echo "Left $(DESTDIR)$(SYSCONFDIR)/config.yaml in place (may contain secrets)."
	@echo "Remove it manually if desired: rm -rf $(DESTDIR)$(SYSCONFDIR)"
	@echo "If the unit was enabled: systemctl disable --now ifnsupdate && systemctl daemon-reload"

help:
	@echo "Targets:"
	@echo "  all / build   Build $(OUT) (default)"
	@echo "  test          Run go test ./..."
	@echo "  vet           Run go vet ./..."
	@echo "  clean         Remove $(OUTDIR)/ (and legacy ./$(BINARY))"
	@echo "  install       Install binary, config example, and systemd unit"
	@echo "  uninstall     Remove binary and unit (keeps config.yaml)"
	@echo
	@echo "Variables (override with make VAR=value):"
	@echo "  PREFIX=$(PREFIX)  BINDIR=$(BINDIR)  OUTDIR=$(OUTDIR)"
	@echo "  SYSCONFDIR=$(SYSCONFDIR)  UNITDIR=$(UNITDIR)"
	@echo "  DESTDIR=$(DESTDIR)  GO=$(GO)"
