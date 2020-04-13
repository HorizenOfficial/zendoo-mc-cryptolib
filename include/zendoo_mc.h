#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

extern "C" {

#ifdef WIN32
    typedef uint16_t codeunit;
#else
    typedef uint8_t codeunit;
#endif

//Field related functions
    typedef struct field field_t;

    //Get the byte size of a generic field_element
    size_t zendoo_get_field_size_in_bytes(void);

    //Serialize a field into field_bytes given an opaque pointer to it
    bool zendoo_serialize_field(
        const field_t*  field,
        unsigned char*  field_bytes
    );

    //Get an opaque pointer to a field built from its byte serialization
    field_t* zendoo_deserialize_field(const unsigned char* field_bytes);

    //Free memory from allocated field_t
    void zendoo_field_free(field_t* field);

//SC SNARK related functions

    typedef struct backward_transfer{
      unsigned char pk_dest[32];
      uint64_t amount;
    } backward_transfer_t;

    typedef struct sc_proof sc_proof_t;

    typedef struct sc_vk sc_vk_t;

    sc_vk_t* zendoo_deserialize_sc_vk_from_file(
        const codeunit* vk_path,
        size_t vk_path_len
    );

    void zendoo_sc_vk_free(sc_vk_t* sc_vk);

    //Get the byte size of a sc zk proof
    size_t zendoo_get_sc_proof_size(void);

    bool zendoo_verify_sc_proof(
        const unsigned char* end_epoch_mc_b_hash,
        const unsigned char* prev_end_epoch_mc_b_hash,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        uint64_t quality,
        const field_t* constant,
        const sc_proof_t* sc_proof,
        const sc_vk_t* sc_vk
    );

    //Serialize a sc zk proof into sc_proof_bytes given an opaque pointer to it
    bool zendoo_serialize_sc_proof(
        const sc_proof_t* sc_proof,
        unsigned char* sc_proof_bytes
    );

    //Get an opaque pointer to a sc_proof built from its byte serialization
    sc_proof_t* zendoo_deserialize_sc_proof(const unsigned char* sc_proof_bytes);

    void zendoo_sc_proof_free(sc_proof_t* sc_proof);

//Poseidon hash related functions

    field_t* zendoo_compute_poseidon_hash(
        const field_t** input,
        size_t input_len
    );

//Poseidon-based Merkle Tree related functions

    typedef struct ginger_mt      ginger_mt_t;
    typedef struct ginger_mt_path ginger_mt_path_t;

    ginger_mt_t* ginger_mt_new(
        const field_t** leaves,
        size_t leaves_len
    );

    field_t* ginger_mt_get_root(
        const ginger_mt_t* tree
    );

    ginger_mt_path_t* ginger_mt_get_merkle_path(
        const field_t* leaf,
        size_t leaf_index,
        const ginger_mt_t* tree
    );

    bool ginger_mt_verify_merkle_path(
        const field_t* leaf,
        const field_t* mr,
        const ginger_mt_path_t* path
    );

    void ginger_mt_free(
        ginger_mt_t* tree
    );

    void ginger_mt_path_free(
        ginger_mt_path_t* path
    );

//Test functions

    //Get an opaque pointer to a random field element
    field_t* zendoo_get_random_field(void);

    bool zendoo_field_assert_eq(
        const field_t* field_1,
        const field_t* field_2
    );
}

#endif // ZENDOO_MC_INCLUDE_H_