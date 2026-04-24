.NOTPARALLEL :

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%: FORCE
	@echo '$*'='$($*)'

# When invoking a sub-make, keep only the command line variable definitions
# matching the pattern in the filter function.
#
# e.g. invoking:
#   $ make A=1 C=1 print-MAKEOVERRIDES print-MAKEFLAGS
#
# with the following in the Makefile:
#   MAKEOVERRIDES := $(filter A=% B=%,$(MAKEOVERRIDES))
#
# will print:
#   MAKEOVERRIDES = A=1
#   MAKEFLAGS = -- A=1
#
# this is because as the GNU make manual says:
#   The command line variable definitions really appear in the variable
#   MAKEOVERRIDES, and MAKEFLAGS contains a reference to this variable.
#
# and since the GNU make manual also says:
#   variables defined on the command line are passed to the sub-make through
#   MAKEFLAGS
#
# this means that sub-makes will be invoked as if:
#   $(MAKE) A=1 blah blah
MAKEOVERRIDES := $(filter V=%,$(MAKEOVERRIDES))
SOURCES_PATH ?= $(BASEDIR)/sources
WORK_PATH = $(BASEDIR)/work
BASE_CACHE ?= $(BASEDIR)/built
SDK_PATH ?= $(BASEDIR)/SDKs
NO_BOOST ?=
NO_LIBEVENT ?=
NO_QT ?=
NO_QR ?=
NO_BDB ?=
NO_SQLITE ?=
NO_WALLET ?=
NO_ZMQ ?=
NO_UPNP ?=
NO_USDT ?=
MULTIPROCESS ?=
LTO ?=
NO_HARDEN ?=
FALLBACK_DOWNLOAD_PATH ?= https://bitcoincore.org/depends-sources

C_STANDARD ?= c11
CXX_STANDARD ?= c++20

BUILD = $(shell ./config.guess)
PATCHES_PATH = $(BASEDIR)/patches
BASEDIR = $(CURDIR)
HASH_LENGTH:=11
DOWNLOAD_CONNECT_TIMEOUT:=30
DOWNLOAD_RETRIES:=3
HOST_ID_SALT ?= salt
BUILD_ID_SALT ?= salt

ifneq ($(DEBUG),)
release_type=debug
else
release_type=release
endif

base_build_dir=$(WORK_PATH)/build
base_staging_dir=$(WORK_PATH)/staging
base_download_dir=$(WORK_PATH)/download
build:=$(shell ./config.sub $(BUILD))

host:=$(build)
ifneq ($(HOST),)
host:=$(HOST)
endif
HOST ?= $(BUILD)
canonical_host:=$(shell ./config.sub $(HOST))

build_arch =$(firstword $(subst -, ,$(build)))
build_vendor=$(word 2,$(subst -, ,$(build)))
full_build_os:=$(subst $(build_arch)-$(build_vendor)-,,$(build))
build_os:=$(findstring linux,$(full_build_os))
build_os+=$(findstring darwin,$(full_build_os))
build_os+=$(findstring freebsd,$(full_build_os))
build_os+=$(findstring netbsd,$(full_build_os))
build_os+=$(findstring openbsd,$(full_build_os))
build_os:=$(strip $(build_os))
ifeq ($(build_os),)
build_os=$(full_build_os)
endif

host_arch=$(firstword $(subst -, ,$(canonical_host)))
host_vendor=$(word 2,$(subst -, ,$(canonical_host)))
full_host_os:=$(subst $(host_arch)-$(host_vendor)-,,$(canonical_host))
host_os:=$(findstring linux,$(full_host_os))
host_os+=$(findstring darwin,$(full_host_os))
host_os+=$(findstring freebsd,$(full_host_os))
host_os+=$(findstring netbsd,$(full_host_os))
host_os+=$(findstring openbsd,$(full_host_os))
host_os+=$(findstring mingw32,$(full_host_os))

host_os:=$(strip $(host_os))
ifeq ($(host_os),)
host_os=$(full_host_os)
endif

$(host_arch)_$(host_os)_prefix=$(BASEDIR)/$(host)
$(host_arch)_$(host_os)_host=$(host)
host_prefix=$($(host_arch)_$(host_os)_prefix)
build_prefix=$(host_prefix)/native
build_host=$(build)

all: install

include hosts/$(host_os).mk
include hosts/default.mk

host_toolchain_CFLAGS := $(host_CFLAGS)
host_toolchain_CXXFLAGS := $(host_CXXFLAGS)
host_toolchain_LDFLAGS := $(host_LDFLAGS)

include builders/$(build_os).mk
include builders/default.mk

hardening_cmake := $(BASEDIR)/../cmake/module/Hardening.cmake

hardening_probe_extra_args_darwin := -DCMAKE_OSX_SYSROOT=$(OSX_SDK) -DCMAKE_OSX_DEPLOYMENT_TARGET=$(OSX_MIN_VERSION)

define run_hardening_probe
$(1)_hardening_probe_dir := $(WORK_PATH)/hardening_probe/$(2)
$(1)_hardening_mk := $$($(1)_hardening_probe_dir)/hardening.mk
$(1)_needs_probe :=
ifeq ($$(wildcard $$($(1)_hardening_mk)),)
$(1)_needs_probe := 1
else ifneq ($$(shell test $(hardening_cmake) -nt $$($(1)_hardening_mk) && echo 1),)
$(1)_needs_probe := 1
endif
ifdef $(1)_needs_probe
ifneq ($$(shell command -v cmake 2>/dev/null),)
$$(shell rm -rf $$($(1)_hardening_probe_dir) && mkdir -p $$($(1)_hardening_probe_dir) && \
    cmake -S $(BASEDIR)/probes/hardening -B $$($(1)_hardening_probe_dir) \
        -DCMAKE_CXX_COMPILER="$(firstword $(3))" \
        -DCMAKE_CXX_FLAGS="$(wordlist 2,99,$(3)) -O2 $(7)" \
        -DCMAKE_SYSTEM_NAME="$(4)" \
        -DCMAKE_SYSTEM_PROCESSOR="$(5)" \
        -DCMAKE_EXE_LINKER_FLAGS_INIT="$(7)" \
        $(hardening_probe_extra_args_$(6)) \
        >$$($(1)_hardening_probe_dir)/configure.log 2>&1)
endif
endif
endef

host_CXX_prog := $(firstword $(strip $(host_CXX)))
build_CXX_prog := $(firstword $(strip $(build_CXX)))
ifeq ($(host_CXX_prog),)
$(error host_CXX is empty. Ensure the compiler is in PATH.)
endif
ifeq ($(build_CXX_prog),)
$(error build_CXX is empty. Ensure the compiler is in PATH.)
endif
ifneq ($(patsubst -%,,$(host_CXX_prog)),$(host_CXX_prog))
$(error host_CXX first word is a flag, not a compiler path (got: "$(host_CXX_prog)" from host_CXX="$(host_CXX)"). Ensure the compiler is in PATH.)
endif
ifneq ($(patsubst -%,,$(build_CXX_prog)),$(build_CXX_prog))
$(error build_CXX first word is a flag, not a compiler path (got: "$(build_CXX_prog)" from build_CXX="$(build_CXX)"). Ensure the compiler is in PATH.)
endif
ifeq ($(shell command -v $(host_CXX_prog) 2>/dev/null),)
$(error host_CXX "$(host_CXX_prog)" is not executable / not found. host_CXX="$(host_CXX)")
endif
ifeq ($(shell command -v $(build_CXX_prog) 2>/dev/null),)
$(error build_CXX "$(build_CXX_prog)" is not executable / not found. build_CXX="$(build_CXX)")
endif

$(eval $(call run_hardening_probe,host,$(host),$(strip $(host_CXX)),$($(host_os)_cmake_system_name),$(host_arch),$(host_os),$(host_toolchain_LDFLAGS)))
$(eval $(call run_hardening_probe,build,$(build),$(strip $(build_CXX)),$($(build_os)_cmake_system_name),$(build_arch),$(build_os),$(build_LDFLAGS)))

ifeq ($(wildcard $(host_hardening_mk)),)
$(error Hardening probe failed for host $(host). See $(host_hardening_probe_dir)/configure.log)
endif
ifeq ($(wildcard $(build_hardening_mk)),)
$(error Hardening probe failed for build $(build). See $(build_hardening_probe_dir)/configure.log)
endif

-include $(host_hardening_mk)
host_probe_workaround_cflags := $(workaround_cflags)
host_probe_workaround_cxxflags := $(workaround_cxxflags)
host_probe_hardening_cflags := $(hardening_cflags)
host_probe_hardening_cxxflags := $(hardening_cxxflags)
host_probe_hardening_ldflags := $(hardening_ldflags)

hardening_cflags :=
hardening_cxxflags :=
hardening_ldflags :=
workaround_cflags :=
workaround_cxxflags :=
-include $(build_hardening_mk)
build_probe_workaround_cflags := $(workaround_cflags)
build_probe_workaround_cxxflags := $(workaround_cxxflags)
build_probe_hardening_cflags := $(hardening_cflags)
build_probe_hardening_cxxflags := $(hardening_cxxflags)
build_probe_hardening_ldflags := $(hardening_ldflags)

$(host_arch)_$(host_os)_CFLAGS += $(host_probe_workaround_cflags)
$(host_arch)_$(host_os)_CXXFLAGS += $(host_probe_workaround_cxxflags)
build_$(build_arch)_$(build_os)_CFLAGS += $(build_probe_workaround_cflags)
build_$(build_arch)_$(build_os)_CXXFLAGS += $(build_probe_workaround_cxxflags)
ifeq ($(NO_HARDEN),)
$(host_arch)_$(host_os)_CFLAGS += $(host_probe_hardening_cflags)
$(host_arch)_$(host_os)_CXXFLAGS += $(host_probe_hardening_cxxflags)
$(host_arch)_$(host_os)_LDFLAGS += $(host_probe_hardening_ldflags)
build_$(build_arch)_$(build_os)_CFLAGS += $(build_probe_hardening_cflags)
build_$(build_arch)_$(build_os)_CXXFLAGS += $(build_probe_hardening_cxxflags)
build_$(build_arch)_$(build_os)_LDFLAGS += $(build_probe_hardening_ldflags)
endif

include packages/packages.mk

# Previously, we directly invoked the well-known programs using $(shell ...)
# to construct build_id_string. However, that was problematic because:
#
# 1. When invoking a shell, GNU Make special-cases exit code 127 (command not
#    found) by not capturing the output but instead passing it through. This is
#    not done for any other exit code.
#
# 2. Characters like '#' (from these programs' output) would end up in make
#    variables like build_id_string, which would be wrongly interpreted by make
#    when these variables were used.
#
# Therefore, we should avoid having arbitrary strings in make variables where
# possible. The gen_id script used here hashes the output to construct a
# "make-safe" id.
#
# Also note that these lines need to be:
#
#     1. After including {hosts,builders}/*.mk, since they rely on the tool
#        variables (e.g. build_CC, host_STRIP, etc.) to be set.
#
#     2. Before including packages/*.mk (excluding packages/packages.mk), since
#        they rely on the build_id variables
#
build_id:=$(shell env CC='$(build_CC)' C_STANDARD='$(C_STANDARD)' CXX='$(build_CXX)' CXX_STANDARD='$(CXX_STANDARD)' \
                      AR='$(build_AR)' NM='$(build_NM)' RANLIB='$(build_RANLIB)' STRIP='$(build_STRIP)' SHA256SUM='$(build_SHA256SUM)' \
                      DEBUG='$(DEBUG)' NO_HARDEN='$(NO_HARDEN)' \
                      ./gen_id '$(BUILD_ID_SALT)' 'GUIX_ENVIRONMENT=$(realpath $(GUIX_ENVIRONMENT))')

$(host_arch)_$(host_os)_id:=$(shell env CC='$(host_CC)' C_STANDARD='$(C_STANDARD)' CXX='$(host_CXX)' CXX_STANDARD='$(CXX_STANDARD)' \
                                        CPPFLAGS='$(host_CPPFLAGS)' CFLAGS='$(host_CFLAGS)' CXXFLAGS='$(host_CXXFLAGS)' LDFLAGS='$(host_LDFLAGS)' \
                                        AR='$(host_AR)' NM='$(host_NM)' RANLIB='$(host_RANLIB)' STRIP='$(host_STRIP)' SHA256SUM='$(build_SHA256SUM)' \
                                        DEBUG='$(DEBUG)' LTO='$(LTO)' NO_HARDEN='$(NO_HARDEN)' \
                                        ./gen_id '$(HOST_ID_SALT)' 'GUIX_ENVIRONMENT=$(realpath $(GUIX_ENVIRONMENT))')

boost_packages_$(NO_BOOST) = $(boost_packages)

libevent_packages_$(NO_LIBEVENT) = $(libevent_packages)

qrencode_packages_$(NO_QR) = $(qrencode_$(host_os)_packages)

qt_packages_$(NO_QT) = $(qt_packages) $(qt_$(host_os)_packages) $(qt_$(host_arch)_$(host_os)_packages) $(qrencode_packages_)

bdb_packages_$(NO_BDB) = $(bdb_packages)
sqlite_packages_$(NO_SQLITE) = $(sqlite_packages)
wallet_packages_$(NO_WALLET) = $(bdb_packages_) $(sqlite_packages_)

upnp_packages_$(NO_UPNP) = $(upnp_packages)

zmq_packages_$(NO_ZMQ) = $(zmq_packages)
multiprocess_packages_$(MULTIPROCESS) = $(multiprocess_packages)
usdt_packages_$(NO_USDT) = $(usdt_$(host_os)_packages)

packages += $($(host_arch)_$(host_os)_packages) $($(host_os)_packages) $(boost_packages_) $(libevent_packages_) $(qt_packages_) $(wallet_packages_) $(upnp_packages_) $(usdt_packages_)
native_packages += $($(host_arch)_$(host_os)_native_packages) $($(host_os)_native_packages)

ifneq ($(zmq_packages_),)
packages += $(zmq_packages)
endif

ifeq ($(multiprocess_packages_),)
packages += $(multiprocess_packages)
native_packages += $(multiprocess_native_packages)
endif

all_packages = $(packages) $(native_packages)

meta_depends = Makefile config.guess config.sub funcs.mk builders/default.mk hosts/default.mk hosts/$(host_os).mk builders/$(build_os).mk

include funcs.mk

final_build_id_long+=$(shell $(build_SHA256SUM) toolchain.cmake.in)
final_build_id+=$(shell echo -n "$(final_build_id_long)" | $(build_SHA256SUM) | cut -c-$(HASH_LENGTH))
$(host_prefix)/.stamp_$(final_build_id): $(native_packages) $(packages)
	rm -rf $(@D)
	mkdir -p $(@D)
	echo copying packages: $^
	echo to: $(@D)
	cd $(@D); $(foreach package,$^, $(build_TAR) xf $($(package)_cached); )
	echo To build Bitcoin Core with these packages, pass \'--toolchain $(@D)/toolchain.cmake\' to the first CMake invocation.
	touch $@

ifeq ($(host),$(build))
  crosscompiling=FALSE
else
  crosscompiling=TRUE
endif

$(host_prefix)/toolchain.cmake : toolchain.cmake.in $(host_prefix)/.stamp_$(final_build_id)
	@mkdir -p $(@D)
	sed -e 's|@depends_crosscompiling@|$(crosscompiling)|' \
            -e 's|@host@|$(host)|' \
            -e 's|@host_system_name@|$($(host_os)_cmake_system_name)|' \
            -e 's|@host_system_version@|$($(host_os)_cmake_system_version)|' \
            -e 's|@host_arch@|$(host_arch)|' \
            -e 's|@CC@|$(host_CC)|' \
            -e 's|@CXX@|$(host_CXX)|' \
            -e 's|@OSX_SDK@|$(OSX_SDK)|' \
            -e 's|@AR@|$(host_AR)|' \
            -e 's|@RANLIB@|$(host_RANLIB)|' \
            -e 's|@STRIP@|$(host_STRIP)|' \
            -e 's|@OBJCOPY@|$(host_OBJCOPY)|' \
            -e 's|@OBJDUMP@|$(host_OBJDUMP)|' \
            -e 's|@CFLAGS@|$(strip $(host_toolchain_CFLAGS))|' \
            -e 's|@CFLAGS_RELEASE@|$(strip $(host_release_CFLAGS))|' \
            -e 's|@CFLAGS_DEBUG@|$(strip $(host_debug_CFLAGS))|' \
            -e 's|@CXXFLAGS@|$(strip $(host_toolchain_CXXFLAGS))|' \
            -e 's|@CXXFLAGS_RELEASE@|$(strip $(host_release_CXXFLAGS))|' \
            -e 's|@CXXFLAGS_DEBUG@|$(strip $(host_debug_CXXFLAGS))|' \
            -e 's|@CPPFLAGS@|$(strip $(host_CPPFLAGS))|' \
            -e 's|@CPPFLAGS_RELEASE@|$(strip $(host_release_CPPFLAGS))|' \
            -e 's|@CPPFLAGS_DEBUG@|$(strip $(host_debug_CPPFLAGS))|' \
            -e 's|@LDFLAGS@|$(strip $(host_toolchain_LDFLAGS))|' \
            -e 's|@LDFLAGS_RELEASE@|$(strip $(host_release_LDFLAGS))|' \
            -e 's|@LDFLAGS_DEBUG@|$(strip $(host_debug_LDFLAGS))|' \
            -e 's|@qt_packages@|$(qt_packages_)|' \
            -e 's|@qrencode_packages@|$(qrencode_packages_)|' \
            -e 's|@zmq_packages@|$(zmq_packages_)|' \
            -e 's|@wallet_packages@|$(wallet_packages_)|' \
            -e 's|@bdb_packages@|$(bdb_packages_)|' \
            -e 's|@sqlite_packages@|$(sqlite_packages_)|' \
            -e 's|@upnp_packages@|$(upnp_packages_)|' \
            -e 's|@usdt_packages@|$(usdt_packages_)|' \
            -e 's|@no_harden@|$(NO_HARDEN)|' \
            -e 's|@multiprocess@|$(MULTIPROCESS)|' \
            $< > $@
	touch $@

define check_or_remove_cached
  mkdir -p $(BASE_CACHE)/$(host)/$(package) && cd $(BASE_CACHE)/$(host)/$(package); \
  $(build_SHA256SUM) -c $($(package)_cached_checksum) >/dev/null 2>/dev/null || \
  ( rm -f $($(package)_cached_checksum); \
    if test -f "$($(package)_cached)"; then echo "Checksum mismatch for $(package). Forcing rebuild.."; rm -f $($(package)_cached_checksum) $($(package)_cached); fi )
endef

define check_or_remove_sources
  mkdir -p $($(package)_source_dir); cd $($(package)_source_dir); \
  test -f $($(package)_fetched) && ( test `cat $($(package)_fetched) | wc -l` -eq $(words $($(package)_all_sources)) && \
    $(build_SHA256SUM) -c $($(package)_fetched) >/dev/null 2>/dev/null || \
    ( echo "Checksum missing or mismatched for $(package) source. Forcing re-download."; \
      rm -f $($(package)_all_sources) $($(1)_fetched))) || true
endef

check-packages:
	@$(foreach package,$(all_packages),$(call check_or_remove_cached,$(package));)
check-sources:
	@$(foreach package,$(all_packages),$(call check_or_remove_sources,$(package));)

$(host_prefix)/toolchain.cmake: check-packages

check-packages: check-sources

clean-all: clean
	@rm -rf $(SOURCES_PATH) x86_64* i686* mips* arm* aarch64* powerpc* riscv32* riscv64* s390x*

clean:
	@rm -rf $(WORK_PATH) $(BASE_CACHE) $(BUILD) *.log

install: check-packages $(host_prefix)/toolchain.cmake


download-one: check-sources $(all_sources)

download-osx:
	@$(MAKE) -s HOST=x86_64-apple-darwin download-one
download-linux:
	@$(MAKE) -s HOST=x86_64-unknown-linux-gnu download-one
download-win:
	@$(MAKE) -s HOST=x86_64-w64-mingw32 download-one
download: download-osx download-linux download-win

$(foreach package,$(all_packages),$(eval $(call ext_add_stages,$(package))))

.PHONY: install cached clean clean-all download-one download-osx download-linux download-win download check-packages check-sources
.PHONY: FORCE
$(V).SILENT:
