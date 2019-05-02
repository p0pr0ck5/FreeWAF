OPENRESTY_PREFIX ?= /usr/local/openresty
LUA_LIB_DIR      ?= $(OPENRESTY_PREFIX)/site/lualib
INSTALL_SOFT     ?= ln -s
INSTALL          ?= install
RESTY_BINDIR      = $(OPENRESTY_PREFIX)/bin
OPM               = $(RESTY_BINDIR)/opm
OPM_LIB_DIR      ?= $(OPENRESTY_PREFIX)/site
PWD               = `pwd`
LUAROCKS         ?= luarocks

LIBS       = waf waf.lua htmlentities.lua
C_LIBS     = lua-aho-corasick lua-resty-htmlentities libinjection
OPM_LIBS   = hamishforbes/lua-resty-iputils p0pr0ck5/lua-resty-cookie \
	p0pr0ck5/lua-ffi-libinjection p0pr0ck5/lua-resty-logger-socket
MAKE_LIBS  = $(C_LIBS) decode
SO_LIBS    = libac.so libinjection.so libhtmlentities.so libdecode.so
RULES      = rules
ROCK_DEPS  = "lrexlib-pcre 2.7.2-1" busted luafilesystem

LOCAL_LIB_DIR = lib/resty

.PHONY: all test install clean test-unit test-acceptance test-regression \
test-translate lua-aho-corasick lua-resty-htmlentities libinjection \
clean-libinjection clean-lua-aho-corasick install-opm-libs clean-opm-libs

all: $(MAKE_LIBS) debug-macro

clean: clean-libinjection clean-lua-aho-corasick clean-lua-resty-htmlentities \
	clean-decode clean-libs clean-test clean-debug-macro

clean-debug-macro:
	./tools/debug-macro.sh clean

clean-install: clean-deps
	cd $(LUA_LIB_DIR) && rm -rf $(RULES) && rm -f $(SO_LIBS) && cd resty/ && \
		rm -rf $(LIBS)

clean-decode:
	cd src && make clean

clean-deps: clean-opm-libs clean-rocks

clean-lua-aho-corasick:
	cd lua-aho-corasick && make clean

clean-lua-resty-htmlentities:
	cd lua-resty-htmlentities && make clean
	rm -f lib/resty/htmlentities.lua

clean-libinjection:
	cd libinjection && make clean && git checkout -- .

clean-libs:
	cd lib && rm -f $(SO_LIBS)

clean-opm-libs:
	$(OPM) --install-dir=$(OPM_LIB_DIR) remove $(OPM_LIBS)

clean-rocks:
	for ROCK in $(ROCK_DEPS); do \
		$(LUAROCKS) remove --tree=$(OPENRESTY_PREFIX) $$ROCK; \
	done

clean-test:
	rm -rf t/servroot*

debug-macro:
	./tools/debug-macro.sh

decode:
	cd src/ && make
	cp src/libdecode.so lib/

lua-aho-corasick:
	cd $@ && make PREFIX=/usr
	cp $@/libac.so lib/

lua-resty-htmlentities:
	cd $@ && make
	cp $@/lib/resty/htmlentities.lua lib/resty
	cp $@/libhtmlentities.so lib/

libinjection:
	cd $@ && make all
	cp $@/src/$@.so lib/

test-unit:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/unit

test-acceptance:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/acceptance

test-regression:
	PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove -r ./t/regression

test-translate:
	prove -r ./t/translate/

test-lua-aho-corasick:
	cd lua-aho-corasick && make test

test-lua-resty-htmlentities:
	cd lua-resty-htmlentities && make test

test-libinjection:
	cd libinjection && make check

test: clean all test-unit test-acceptance test-regression test-translate

test-libs: clean all test-lua-aho-corasick test-lua-resty-htmlentities \
	test-libinjection

test-recursive: test test-libs

test-fast: all
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/translate
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/unit
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j16 -r ./t/regression
	TEST_NGINX_RANDOMIZE=1 PATH=$(OPENRESTY_PREFIX)/nginx/sbin:$$PATH prove \
		-j4 -r ./t/acceptance
	rebusted -k -o=TAP ./t/translation/*
	./tools/lua-releng -L

install-check:
	stat lib/*.so > /dev/null

install-deps: install-opm-libs install-rocks

install-opm-libs:
	$(OPM) --install-dir=$(OPM_LIB_DIR) get $(OPM_LIBS)

install-rocks:
	for ROCK in $(ROCK_DEPS); do \
		$(LUAROCKS) install --tree=$(OPENRESTY_PREFIX) $$ROCK; \
	done

install-link: install-check
	$(INSTALL_SOFT) $(PWD)/lib/resty/* $(LUA_LIB_DIR)/resty/
	$(INSTALL_SOFT) $(PWD)/lib/*.so $(LUA_LIB_DIR)
	$(INSTALL_SOFT) $(PWD)/rules/ $(LUA_LIB_DIR)

install: install-check install-deps
	$(INSTALL) -d $(LUA_LIB_DIR)/resty/waf/storage
	$(INSTALL) -d $(LUA_LIB_DIR)/rules
	$(INSTALL) -m 644 lib/resty/*.lua $(LUA_LIB_DIR)/resty/
	$(INSTALL) -m 644 lib/resty/waf/*.lua $(LUA_LIB_DIR)/resty/waf/
	$(INSTALL) -m 644 lib/resty/waf/storage/*.lua $(LUA_LIB_DIR)/resty/waf/storage/
	$(INSTALL) -m 644 lib/*.so $(LUA_LIB_DIR)
	$(INSTALL) -m 644 rules/*.json $(LUA_LIB_DIR)/rules/

install-soft: install-check install-deps install-link
