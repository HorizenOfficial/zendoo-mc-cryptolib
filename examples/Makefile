G++_BIN ?= $(shell which g++)
CARGO_BIN ?= $(shell which cargo)

all: clean build
	./bin_SampleCalls
clean:
	#$(CARGO_BIN) clean
	#rm -f ./bin_SampleCalls
build:
	$(CARGO_BIN) build --release
	$(G++_BIN) -o ./bin_SampleCalls ./sampleCalls.cpp -I../include  -L. -l:../target/release/libzendoo_mc.a -lpthread -ldl