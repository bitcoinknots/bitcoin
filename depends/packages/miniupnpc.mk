package=miniupnpc
$(package)_version=2.3.4_pre20260906
$(package)_commithash=2cb87d04034587bdb0f51549b3936e0d9e143bcb
$(package)_download_path=https://github.com/miniupnp/miniupnp/archive/
$(package)_download_file=$($(package)_commithash).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=0990cbae425c16e3739b2b79f67b5c7c5d333c13513f6b7ff3b16b2567837da2
$(package)_patches=dont_leak_info.patch
$(package)_build_subdir=build

define $(package)_set_vars
$(package)_config_opts = -DUPNPC_BUILD_SAMPLE=OFF -DUPNPC_BUILD_SHARED=OFF
$(package)_config_opts += -DUPNPC_BUILD_STATIC=ON -DUPNPC_BUILD_TESTS=OFF
$(package)_config_opts_mingw32 += -DMINIUPNPC_TARGET_WINDOWS_VERSION=0x0601
endef

define $(package)_extract_cmds
  mkdir -p $$($(package)_extract_dir) && \
  echo "$$($(package)_sha256_hash)  $$($(package)_source)" > $$($(package)_extract_dir)/.$$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $$($(package)_extract_dir)/.$$($(package)_file_name).hash && \
  $(build_TAR) --no-same-owner --strip-components=2 -xf $$($(package)_source) miniupnp-$($(package)_commithash)/$(package)
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/dont_leak_info.patch
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  cmake --install . --prefix $($(package)_staging_prefix_dir)
endef

define $(package)_postprocess_cmds
  rm -rf bin && \
  rm -rf share
endef
