G++_BIN ?= $(shell which g++)
CARGO_BIN ?= $(shell which cargo)

all: clean build
	./bin_SampleCalls --abort-after=1
clean:
	#$(CARGO_BIN) clean
	#rm -f ./bin_SampleCalls
build:
	$(CARGO_BIN) build --release --all-features
	$(G++_BIN) -o ./bin_SampleCalls ./sampleCalls.cpp -I../include  -L. -l:../target/release/libzendoo_mc.a -lpthread -ldl