#include "zendoo_mc.h"
#include "error.h"
#include <iostream>
#include <cassert>
#include <string>

void print_error(const char *msg) {
    Error err = zendoo_get_last_error();

    fprintf(stderr,
            "%s: %s [%d - %s]\n",
            msg,
            err.msg,
            err.category,
            zendoo_get_category_name(err.category));
}

int main(int argc, char** argv)
{
    assert(argc == 7);

    // Parse inputs
    auto end_epoch_mc_b_hash = (unsigned char*) argv[1];
    auto prev_end_epoch_mc_b_hash = (unsigned char*) argv[2];
    auto mr_bt = (unsigned char*) argv[3];
    uint64_t quality = strtoull(argv[4], NULL, 0);
    auto constant = argv[5];
    auto proofdata = argv[6];

    // Deserialize mr_bt, constant and proofdata
    auto mr_bt_f = zendoo_deserialize_field(mr_bt);
    if(mr_bt_f == NULL){
        print_error("Error: ");
        abort();
    }

    field_t* constant_f = NULL;
    if(std::string(constant).size() != 0){
        std::cout << "constant" << std::endl;
        constant_f = zendoo_deserialize_field((unsigned char*)constant);
    }

    field_t* proofdata_f = NULL;
    if(std::string(proofdata).size() != 0){
        std::cout << "proofdata" << std::endl;
        proofdata_f = zendoo_deserialize_field((unsigned char*)proofdata);
    }

    // Generate proof and vk
    if(!create_mc_test_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        mr_bt_f,
        quality,
        constant_f,
        proofdata_f
    )){
        print_error("Error: ");
        abort();
    }

    zendoo_field_free(mr_bt_f);

    if(constant_f != NULL)
        zendoo_field_free(constant_f);

    if(proofdata_f != NULL)
        zendoo_field_free(proofdata_f);
}