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
    typedef struct ginger_mt      ginger_mt_t;
    typedef struct ginger_mt_path ginger_mt_path_t;

    ginger_mt_t* ginger_mt_new(
        const unsigned char* leaves,
        size_t leaves_len
    );

    bool ginger_mt_get_root(
        const ginger_mt_t* tree,
        unsigned char* mr
    );

    ginger_mt_path_t* ginger_mt_get_merkle_path(
        const unsigned char* leaf,
        size_t leaf_index,
        const ginger_mt_t* tree
    );

    bool ginger_mt_verify_merkle_path(
        const unsigned char* leaf,
        const unsigned char* mr,
        const ginger_mt_path_t* path
    );

    void ginger_mt_free(
        ginger_mt_t* tree
    );

    void ginger_mt_path_free(
        ginger_mt_path_t* path
    );

    //Test functions
    bool zendoo_get_random_fr(
        unsigned char* result
    );
}

#endif // ZENDOO_MC_INCLUDE_H_