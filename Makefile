PREFIX=		/home/majid/local
#PREFIX=	/usr/local
SSL_HOME=	$(shell openssl version -a | grep OPENSSLDIR | cut -d " " -f 2|tr -d '"')
ENV=		env CARGO_BACKTRACE=1 OPENSSL_DIR=$(SSL_HOME) \
		PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig:/usr/lib/pkgconfig \
		RUSTFLAGS="-C link-arg=-Wl,-rpath,$(SSL_HOME)/lib"

CARGO=		$(ENV) cargo

.PHONY: all build release check test run clean

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

check:
	$(CARGO) check

test:
	$(CARGO) test

run:
	$(CARGO) run

clean:
	$(CARGO) clean
