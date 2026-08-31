package=jansson
$(package)_version=2.14.1
$(package)_download_path=https://github.com/akheron/jansson/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=2521cd51a9641d7a4e457f7215a4cd5bb176f690bc11715ddeec483e85d9e2b3

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --disable-docs
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf bin share
endef
