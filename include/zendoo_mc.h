#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

extern "C" {

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

//Pk related functions

    typedef struct pk pk_t;

    //Get the byte size of pk
    size_t zendoo_get_pk_size_in_bytes(void);

    //Serialize a pk into pk_bytes given an opaque pointer to it
    bool zendoo_serialize_pk(
        const pk_t*    pk,
        unsigned char* pk_bytes
    );

    //Get an opaque pointer to a pk built from its byte serialization
    pk_t* zendoo_deserialize_pk(const unsigned char* pk_bytes);

    //Free memory from allocated field_t
    void zendoo_pk_free(pk_t* pk);

//SNARK related functions

    typedef struct ginger_zk_proof ginger_zk_proof_t;

    //Get the byte size of a generic zk proof
    size_t get_ginger_zk_proof_size(void);

    //Serialize a zk proof into zk_proof_bytes given an opaque pointer to it
    bool serialize_ginger_zk_proof(
        const ginger_zk_proof_t* zk_proof,
        unsigned char*           zk_proof_bytes
    );

    //Get an opaque pointer to a zk_proof built from its byte serialization
    ginger_zk_proof_t* deserialize_ginger_zk_proof(const unsigned char* ginger_zk_proof_bytes);

    bool verify_ginger_zk_proof(
        const uint8_t* vk_path,
        size_t vk_path_len,
        const ginger_zk_proof_t* zkp,
        const field_t** public_inputs,
        size_t public_inputs_len
    );

    void ginger_zk_proof_free(ginger_zk_proof_t* zkp);

//Poseidon hash related functions

    field_t* zendoo_compute_poseidon_hash(
        const field_t** input,
        size_t input_len
    );

    field_t* zendoo_compute_keys_hash_commitment(
        const pk_t** pks,
        size_t pk_num
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

    pk_t* zendoo_get_random_pk(void);

    bool zendoo_pk_assert_eq(
        const pk_t* pk_1,
        const pk_t* pk_2
    );
}

#endif // ZENDOO_MC_INCLUDE_H_