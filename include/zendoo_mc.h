#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

extern "C" {
    //SNARK related functions
    bool zendoo_verify_zkproof(
        const uint8_t* vk_path,
        size_t vk_path_len,
        const unsigned char* zkp,
        const unsigned char* public_inputs,
        size_t public_inputs_len
    );

    //Poseidon hash related functions
    bool zendoo_compute_poseidon_hash(
        const unsigned char* input,
        size_t input_len,
        unsigned char* result
    );

    bool zendoo_compute_keys_hash_commitment(
        const unsigned char* pks,
        size_t pks_len,
        unsigned char* h_cm
    );

    //Poseidon-based Merkle Tree related functions
    bool zendoo_compute_merkle_root(
        const unsigned char* leaves,
        size_t leaves_len,
        unsigned char* mr
    );

    //Test functions
    bool zendoo_get_random_fr(
        unsigned char* result
    );
}

#endif // ZENDOO_MC_INCLUDE_H_