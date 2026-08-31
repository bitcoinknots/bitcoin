package=curl
$(package)_version=8.11.1
$(package)_download_path=https://curl.se/download/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=c7ca7db48b0909743eaef34250da02c19bc61d4f1dcedd6603f109409536ab56

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --disable-docs --disable-manual
  $(package)_config_opts+=--disable-dict --disable-file --disable-ftp --disable-gopher --disable-imap
  $(package)_config_opts+=--disable-ldap --disable-ldaps --disable-mqtt --disable-pop3 --disable-rtsp
  $(package)_config_opts+=--disable-smb --disable-smtp --disable-telnet --disable-tftp
  $(package)_config_opts+=--without-brotli --without-libidn2 --without-libpsl --without-librtmp
  $(package)_config_opts+=--without-libssh2 --without-nghttp2 --without-ssl --without-zlib --without-zstd
  $(package)_config_opts+=--enable-http --enable-ipv6
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -C lib
endef

define $(package)_stage_cmds
  $(MAKE) -C lib DESTDIR=$($(package)_staging_dir) install && \
  $(MAKE) -C include DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf bin share
endef
