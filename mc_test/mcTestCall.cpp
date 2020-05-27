#include "zendoo_mc.h"
#include "hex_utils.h"
#include <iostream>
#include <cassert>
#include <string>

/*
 *  Usage: ./mcTest "end_epoch_mc_b_hash" "prev_end_epoch_mc_b_hash" "mr_bt" "quality" "<constant>" "<proofdata>"
 *  "constant" and "proofdata" can be null but the "" must be specified anyway
 */

int main(int argc, char** argv)
{
    assert(argc == 7);

    // Parse inputs
    assert(IsHex(argv[1]));
    auto end_epoch_mc_b_hash = ParseHex(argv[1]);
    assert(end_epoch_mc_b_hash.size() == 32);

    assert(IsHex(argv[2]));
    auto prev_end_epoch_mc_b_hash = ParseHex(argv[2]);
    assert(prev_end_epoch_mc_b_hash.size() == 32);

    assert(IsHex(argv[3]));
    auto mr_bt = ParseHex(argv[3]);
    assert(mr_bt.size() == 96);

    uint64_t quality = strtoull(argv[4], NULL, 0);
    assert(quality >= 0);

    auto constant = std::string(argv[5]);
    auto proofdata = std::string(argv[6]);

    // Deserialize mr_bt, constant and proofdata
    auto mr_bt_f = zendoo_deserialize_field((unsigned char*)mr_bt.data());
    assert(mr_bt_f != NULL);

    field_t* constant_f = NULL;
    if(constant.size() != 0){
        assert(IsHex(constant));
        auto constant_decoded = ParseHex(constant.c_str());
        assert(constant_decoded.size() == 96);
        constant_f = zendoo_deserialize_field((unsigned char*)constant_decoded.data());
        assert(constant_f != NULL);
    }

    field_t* proofdata_f = NULL;
    if(proofdata.size() != 0){
        assert(IsHex(proofdata));
        auto proofdata_decoded = ParseHex(proofdata.c_str());
        assert(proofdata_decoded.size() == 96);
        proofdata_f = zendoo_deserialize_field((unsigned char*)proofdata_decoded.data());
        assert(proofdata_f != NULL);
    }

    // Generate proof and vk
    assert(zendoo_create_mc_test_proof(
        end_epoch_mc_b_hash.data(),
        prev_end_epoch_mc_b_hash.data(),
        mr_bt_f,
        quality,
        constant_f,
        proofdata_f
    ));

    zendoo_field_free(mr_bt_f);

    if(constant_f != NULL)
        zendoo_field_free(constant_f);

    if(proofdata_f != NULL)
        zendoo_field_free(proofdata_f);
}