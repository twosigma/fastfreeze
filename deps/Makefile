# The change of these two variables must be reflected in ../src/consts.rs
INTERPOSED_LD_PATH=/var/fastfreeze/run/ld-linux-x86-64.so.2
LD_INJECT_ENV_PATH=/var/fastfreeze/ld-inject.env

RUSTUP_DEP_FILE=.deps-rustup-$(shell hostname)
$(RUSTUP_DEP_FILE):
	which rustc || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	touch $@

# debian/ubuntu dependencies
DEPS_FILE=.deps-debian-v1-$(shell hostname)
$(DEPS_FILE):
	[ -e criu/Makefile ] || (git submodule sync && git submodule update --init)
	sudo apt-get install -y --no-install-recommends \
		build-essential pkg-config \
		libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler \
		libbsd-dev iproute2 libcap-dev libnl-3-dev libnet-dev libaio-dev \
		patchelf pv liblz4-tool zstd jq wget openssl
	touch $@

BUILDS := \
	build_criu \
	build_libvirtcpuid \
	build_libvirttime \
	build_criu_image_streamer \
	build_set_ns_last_pid \

.PHONY: $(BUILDS) clean

all: $(BUILDS)

build_criu: | $(DEPS_FILE)
	$(MAKE) -C criu criu

build_libvirtcpuid: | $(DEPS_FILE)
	$(MAKE) -C libvirtcpuid \
		INTERPOSED_LD_PATH=$(INTERPOSED_LD_PATH) \
		LD_INJECT_ENV_PATH=$(LD_INJECT_ENV_PATH)

build_libvirttime: | $(DEPS_FILE)
	$(MAKE) -C libvirttime

build_criu_image_streamer: | $(DEPS_FILE) $(RUSTUP_DEP_FILE)
	$(MAKE) -C criu-image-streamer

build_set_ns_last_pid: | $(DEPS_FILE)
	$(MAKE) -C set_ns_last_pid

clean:
	$(MAKE) -C criu mrproper
	$(MAKE) -C libvirtcpuid clean
	$(MAKE) -C libvirttime clean
	$(MAKE) -C criu-image-streamer clean
	$(MAKE) -C set_ns_last_pid clean
