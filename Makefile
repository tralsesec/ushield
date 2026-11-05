PREFIX ?= /usr/local
DIST_DIR ?= dist

.PHONY: all daemon kernel clean install install-dist

all: daemon kernel

daemon:
	@echo "=== Building Userspace Daemon (ushieldd) ==="
	$(MAKE) -C daemon

kernel:
	@echo "=== Building Kernel Module (ushield.ko) ==="
	$(MAKE) -C kernel

clean:
	$(MAKE) -C daemon clean
	$(MAKE) -C kernel clean
	rm -rf $(DIST_DIR)

# Local staging directory for easy VM copying / packaging
install-dist: all
	@echo "=== Staging artifacts into ./$(DIST_DIR) ==="
	mkdir -p $(DIST_DIR)/bin $(DIST_DIR)/module
	cp daemon/ushieldd $(DIST_DIR)/bin/
	cp kernel/ushield.ko $(DIST_DIR)/module/
	cp configs/ushield.conf $(DIST_DIR)/

# Direct system installation
install: all
	@echo "=== Installing ushieldd to $(PREFIX)/bin ==="
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 daemon/ushieldd $(DESTDIR)$(PREFIX)/bin/
	@echo "=== Installing ushield.ko ==="
	$(MAKE) -C kernel modules_install
