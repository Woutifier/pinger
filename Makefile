CARGO = cargo

CARGO_OPTS =

all:
	$(MAKE) build

build:
	$(CARGO) $(CARGO_OPTS) build --release

clean:
	$(CARGO) $(CARGO_OPTS) clean

check:
	$(MAKE) build
	$(MAKE) test

test:
	$(CARGO) $(CARGO_OPTS) test

bench:
	$(CARGO) $(CARGO_OPTS) bench

doc:
	$(CARGO) $(CARGO_OPTS) doc

.PHONY: all build clean check test bench doc
