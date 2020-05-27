#include "zendoo_mc.h"
#include "hex_utils.h"
#include <iostream>
#include <cassert>
#include <string>

/*
 *  Usage: ./getBtMr "pk_dest_0" "amount_0" "pk_dest_1" "amount_1" ... "pk_dest_n" "amount_n"
 */
int main(int argc, char** argv)
{
    // Inputs must be (pk_dest, amount) pairs from which construct backward_transfer objects
    assert((argc - 1) % 2 == 0);

    // Parse backward transfer list
    std::vector<backward_transfer_t> bt_list;
    bt_list.reserve((argc - 1) % 2);
    for(int i = 1; i < argc - 1; i += 2){
        backward_transfer_t bt;

        assert(IsHex(argv[i]));
        auto pk_dest = ParseHex(argv[i]);
        assert(pk_dest.size() == 20);

        uint64_t amount = strtoull(argv[i + 1], NULL, 0);
        assert(amount >= 0);
        bt.amount = amount;

        bt_list.push_back(bt);
    }

    // Compute mr_bt
    auto mr_bt = zendoo_get_mr_bt(bt_list.data(), bt_list.size());
    assert(mr_bt != NULL);

    // Serialize it to byte array
    unsigned char mr_bt_bytes[96];
    zendoo_serialize_field(mr_bt, mr_bt_bytes);
    assert(sizeof(mr_bt_bytes) == 96);

    // Free memory
    zendoo_field_free(mr_bt);

    // Output bytes
    std::cout << EncodeHex(mr_bt_bytes, 96);
}