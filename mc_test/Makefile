CXX ?= g++
CARGO_BIN ?= cargo
PYTHON_BIN ?= python3
EXECUTABLES = $(CXX) $(CARGO_BIN) $(PYTHON_BIN)
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell PATH="${PATH}" command -v $(exec)),,$(error "No $(exec) in PATH")))

# support also not-so-new compilers
CXX_FLAGS += -std=c++11

ifeq ($(shell env | grep RUSTFLAGS),)
        RUSTFLAGS := -C target-feature=+bmi2,+adx --emit=asm
endif
RUST_FILES := $(shell find ../src/ -type f -name '*.rs')
CARGO_FILES := $(shell find ../ -maxdepth 1 -type f -name '*.toml' -or -name '*.lock')
RUST_LIB := ../target/release/libzendoo_mc.a
MCTEST_LIB := ../target/release/libmcTestCall.a
MCTEST_OBJ := ./mcTestCall.o
MCTEST_LIB_SOURCES := ./mcTestCall.cpp
CXX_FILE := ./mcTestCallMain.cpp
INCLUDE := ../include
INCLUDE_FILES := $(wildcard $(INCLUDE)/*.h)

.PHONY: all
all: clean test

.PHONY: clean-cargo
clean-cargo:
	RUSTFLAGS='$(RUSTFLAGS)' $(CARGO_BIN) $(CARGOARGS) clean

.PHONY: clean-lib
clean-lib:
	rm -f $(MCTEST_OBJ) $(MCTEST_LIB)

.PHONY: clean-test
clean-test:
	rm -f ./mcTest

.PHONY: clean
clean: clean-cargo clean-lib clean-test

.PHONY: libs
libs: $(RUST_LIB)

$(RUST_LIB): $(CARGO_FILES) $(RUST_FILES)
	RUSTFLAGS='$(RUSTFLAGS)' $(CARGO_BIN) $(CARGOARGS) build --release --all-features

$(MCTEST_OBJ): $(MCTEST_LIB_SOURCES) $(INCLUDE_FILES)
	$(CXX) $(CXX_FLAGS) -c $(MCTEST_LIB_SOURCES) -I$(INCLUDE)

$(MCTEST_LIB): $(MCTEST_OBJ)
	mkdir -p $(@D)
	$(AR) rcs $@ $+

.PHONY: mcTestLib
mcTestLib: libs $(MCTEST_LIB)

./mcTest: $(CXX_FILE) $(INCLUDE_FILES) mcTestLib
	$(CXX) $(CXX_FLAGS) -o $@ $(CXX_FILE) -I$(INCLUDE) -L. -l:$(MCTEST_LIB) -l:$(RUST_LIB) -lpthread -ldl

.PHONY: test-cert
test-cert: mcTest
	$(PYTHON_BIN) ./callFromMTFExample.py -t cert

.PHONY: test-cert-keyrot
test-cert-keyrot: mcTest
	$(PYTHON_BIN) ./callFromMTFExample.py -t cert -r

.PHONY: test-csw
test-csw: mcTest
	$(PYTHON_BIN) ./callFromMTFExample.py -t csw

.PHONY: test
test: test-cert test-cert-keyrot test-csw
