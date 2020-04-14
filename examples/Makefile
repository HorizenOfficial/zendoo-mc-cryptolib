ifeq ($(OS),Windows_NT)
    LIBZENDOO = ../target/debug/zendoo_mc.lib
else
    LIBZENDOO = ../target/debug/libzendoo_mc.a
endif

all: clean build
	./bin_SampleCalls
clean:
	cargo clean
	rm -f ./bin_SampleCalls
build:
	cargo build
	g++ -o ./bin_SampleCalls ./sampleCalls.cpp -I../include  -L. -l:$(LIBZENDOO) -lpthread -ldl
