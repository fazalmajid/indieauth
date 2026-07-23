CARGO=		cargo

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
