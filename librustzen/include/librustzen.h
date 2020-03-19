#ifndef LIBRUSTZEN_INCLUDE_H_
#define LIBRUSTZEN_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h> //TODO: Zcash seems to have only the above import and it sees size_t. Why ?

extern "C" {
    //SNARK related functions
    bool librustzen_verify_zkproof(
        const uint8_t* vk_path,
        size_t vk_path_len,
        const unsigned char* zkp,
        const unsigned char* public_inputs,
        size_t public_inputs_len
    );

    //Schnorr signature related functions
    bool librustzen_sign_keygen(
        unsigned char* sk_result,
        unsigned char* pk_result
    );

    bool librustzen_sign_key_verify(
        const unsigned char* pk
    );

    bool librustzen_sign_message(
        const unsigned char* message,
        size_t message_len,
        const unsigned char* sk,
        const unsigned char* pk,
        unsigned char* result
    );

    bool librustzen_sign_verify(
        const unsigned char* message,
        size_t message_len,
        const unsigned char* pk,
        const unsigned char* sig
    );

    //Poseidon hash related functions
    bool librustzen_compute_poseidon_hash(
        const unsigned char* input,
        size_t input_len,
        unsigned char* result
    );

    bool librustzen_compute_keys_hash_commitment(
        const unsigned char* pks,
        size_t pks_len,
        unsigned char* h_cm
    );

    //VRF related functions

    bool librustzen_vrf_keygen(
        unsigned char* sk_result,
        unsigned char* pk_result
    );

    bool librustzen_vrf_key_verify(
        const unsigned char* pk
    );

    bool librustzen_vrf_create_proof(
        const unsigned char* message,
        size_t message_len,
        const unsigned char* sk,
        const unsigned char* pk,
        unsigned char* result
    );

    bool librustzen_vrf_proof_to_hash(
        const unsigned char* message,
        size_t message_len,
        const unsigned char* pk,
        const unsigned char* proof,
        unsigned char* result
    );

    bool librustzen_vrf_proof_verify(
        const unsigned char* message,
        size_t message_len,
        const unsigned char* pk,
        const unsigned char* proof,
        unsigned char* result
    );

    //Test functions
    bool librustzen_get_random_fr(
        unsigned char* result
    );
}

#endif // LIBRUSTZEN_INCLUDE_H_