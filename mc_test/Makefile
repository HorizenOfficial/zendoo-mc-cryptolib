G++_BIN ?= $(shell which g++)
CARGO_BIN ?= $(shell which cargo)

all: clean build
clean:
	$(CARGO_BIN) clean
	rm -f ./mcTest
build:
	RUSTFLAGS="-C target-feature=+bmi2,+adx --emit=asm" $(CARGO_BIN) +nightly-2021-04-25 build --release --all-features
	$(G++_BIN) -o ./mcTest ./mcTestCall.cpp -I../include  -L. -l:../target/release/libzendoo_mc.a -lpthread -ldl