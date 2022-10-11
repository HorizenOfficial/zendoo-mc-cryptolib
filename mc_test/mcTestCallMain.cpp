#include "mcTestCall.h"
#include "hex_utils.h" // mc_crypto_lib version

static const int SEGMENT_SIZE = 1 << 18;

int main(int argc, char** argv) {
    run(argc,
        argv,
        SEGMENT_SIZE,
        [](const char* in, std::vector<unsigned char>& out) {
            out = SetHex(in, 20);
            return true;
        });
}

