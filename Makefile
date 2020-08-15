#       Copyright 2020 Two Sigma Investments, LP.
#
#       Licensed under the Apache License, Version 2.0 (the "License");
#       you may not use this file except in compliance with the License.
#       You may obtain a copy of the License at
#
#           http://www.apache.org/licenses/LICENSE-2.0
#
#       Unless required by applicable law or agreed to in writing, software
#       distributed under the License is distributed on an "AS IS" BASIS,
#       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#       See the License for the specific language governing permissions and
#       limitations under the License.

#BUILD := debug
BUILD := release

BUILD_FLAGS :=
ifeq ($(BUILD),release)
	BUILD_FLAGS += --release
endif

CARGO := $(HOME)/.cargo/bin/cargo
ifeq (,$(wildcard $(CARGO)))
	CARGO := cargo
endif

SRCS := $(wildcard src/*.rs) Cargo.toml

all: fastfreeze.tar.xz

deps/%:
	$(MAKE) -C deps

DIST_DIR = dist
DIST_LIB_DIR = $(DIST_DIR)/lib

$(DIST_DIR):
	mkdir -p $@

$(DIST_LIB_DIR):
	mkdir -p $@

DIST_BINS := \
	deps/criu/criu/criu \
	deps/criu-image-streamer/criu-image-streamer \
	deps/set_ns_last_pid/set_ns_last_pid \
	target/$(BUILD)/fastfreeze \
	$(shell which pv) \
	$(shell which lz4) \
	$(shell which zstd) \

DIST_LIBS := \
	deps/libvirtcpuid/ld-virtcpuid.so \
	deps/libvirtcpuid/libvirtcpuid.so \
	deps/libvirttime/libvirttime.so \

DIST_MISC := fastfreeze_wrapper.sh \

define add_dist_file
$(eval SRC_FILE := $(1))
$(eval DST_DIR := $(2))
$(eval DST_FILE := $(DST_DIR)/$(notdir $(SRC_FILE)))

DIST_FILES += $(DST_FILE)
$(DST_FILE): $(SRC_FILE) | $(DST_DIR)
	cp -aL $$< $$@
endef

$(foreach path,$(DIST_BINS),$(eval \
	$(call add_dist_file,$(path),$(DIST_DIR)) \
	$(eval DIST_ELF_FILES += $(DST_FILE)) \
))

$(foreach path,$(DIST_LIBS),$(eval \
	$(call add_dist_file,$(path),$(DIST_LIB_DIR)) \
	$(eval DIST_ELF_FILES += $(DST_FILE)) \
))

$(foreach path,$(DIST_MISC),$(eval \
	$(call add_dist_file,$(path),$(DIST_DIR)) \
))

target/$(BUILD)/fastfreeze: $(SRCS)
	$(CARGO) build $(BUILD_FLAGS)

.PHONY: test clean extract-libs

clean:
	rm -rf target $(DIST_DIR)
	@echo Dependencies are not cleaned. You may do so with: make -C deps clean

extract-libs: $(DIST_ELF_FILES) | $(DIST_LIB_DIR)
	ldd $(DIST_ELF_FILES) | sed 's/.*=> \(.*\) .*/\1/;t;d' | \
		sort -u | \
		xargs realpath -s | \
		grep -v $(DIST_LIB_DIR)/ | \
		xargs -I'{}' cp -L '{}' $(DIST_LIB_DIR)/
	for file in $$(echo $(DIST_ELF_FILES) $(DIST_LIB_DIR)/* | \
			tr " " "\n" | sort -u | grep -v 'ld-.*.so'); do \
		RPATH=`echo $$file | sed -E 's|^$(DIST_DIR)|| ; s|[^/]+/|../|g ; s|[^/]+$$|lib| ; s|^|$$ORIGIN|'`; \
		: " \
		We are are doing setcap on criu's binary, and that makes it \
		secure. Some distro don't interpret $ORIGIN on secure binaries \
		So we'll hard code /opt/fastfreeze/lib as RPATH \
		"; \
		RPATH=/opt/fastfreeze/lib; \
		echo "Patching rpath=$$RPATH of $$file"; \
		patchelf --set-rpath $$RPATH $$file ;\
	done

fastfreeze.tar.xz: $(DIST_FILES) extract-libs Makefile
	tar --transform 's|^$(DIST_DIR)|fastfreeze|' -cJf $@ $(DIST_DIR)
