G++_BIN ?= $(shell which g++)
CARGO_BIN ?= $(shell which cargo)

all: clean build
clean:
	$(CARGO_BIN) clean
	rm -f ./bin_SampleCalls
build:
	$(CARGO_BIN) build --release --all-features
	$(G++_BIN) -o ./mcTest ./mcTestCall.cpp -I../include  -L. -l:../target/release/libzendoo_mc.a -lpthread -ldl