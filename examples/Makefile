G++_BIN ?= $(shell which g++)
CARGO_BIN ?= $(shell which cargo)

all: clean build
	./bin_SampleCalls --abort-after=1
clean:
	#$(CARGO_BIN) clean
	#rm -f ./bin_SampleCalls
build:
	RUSTFLAGS="-C target-feature=+bmi2,+adx --emit=asm" $(CARGO_BIN) +nightly-2021-04-25 build --release --all-features
	$(G++_BIN) -o ./bin_SampleCalls ./sampleCalls.cpp -I../include  -L. -l:../target/release/libzendoo_mc.a -lpthread -ldl