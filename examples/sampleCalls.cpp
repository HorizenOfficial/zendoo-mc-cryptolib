#include "zendoo_mc.h"
#include "error.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

void field_test() {
    //Size is the expected one
    int field_len = zendoo_get_field_size_in_bytes();
    if(field_len != 96) {
        std::cout << "Unexpected size" << std::endl;
        return;
    }

    auto field = zendoo_get_random_field();

    //Serialize and deserialize and check equality
    unsigned char field_bytes[96];
    if (!zendoo_serialize_field(field, field_bytes)){
        print_error("error:");
        return;
    }

    auto field_deserialized = zendoo_deserialize_field(field_bytes);
    if (field_deserialized == NULL) {
        print_error("error: ");
        return;
    }

    if (!zendoo_field_assert_eq(field, field_deserialized)) {
        std::cout << "Unexpected deserialized field" << std::endl;
        return;
    };

    zendoo_field_free(field);
    zendoo_field_free(field_deserialized);

    std::cout<< "Field test...ok" << std::endl;
}

void pk_test() {
    //Size is the expected one
    int pk_len = zendoo_get_pk_size_in_bytes();
    if(pk_len != 193) {
        std::cout << "Unexpected size" << std::endl;
        return;
    }

    auto pk = zendoo_get_random_pk();

    //Serialize and deserialize and check equality
    unsigned char pk_bytes[pk_len];
    if (!zendoo_serialize_pk(pk, pk_bytes)){
        print_error("error:");
        return;
    }

    auto pk_deserialized = zendoo_deserialize_pk(pk_bytes);
    if (pk_deserialized == NULL) {
        print_error("error: ");
        return;
    }

    if (!zendoo_pk_assert_eq(pk, pk_deserialized)) {
        std::cout << "Unexpected deserialized pk" << std::endl;
        return;
    };

    zendoo_pk_free(pk);
    zendoo_pk_free(pk_deserialized);

    std::cout<< "Pk test...ok" << std::endl;
}

void hash_test() {
    unsigned char lhs[96] = {
        138, 206, 199, 243, 195, 254, 25, 94, 236, 155, 232, 182, 89, 123, 162, 207, 102, 52, 178, 128, 55, 248, 234,
        95, 33, 196, 170, 12, 118, 16, 124, 96, 47, 203, 160, 167, 144, 153, 161, 86, 213, 126, 95, 76, 27, 98, 34, 111,
        144, 36, 205, 124, 200, 168, 29, 196, 67, 210, 100, 154, 38, 79, 178, 191, 246, 115, 84, 232, 87, 12, 34, 72,
        88, 23, 236, 142, 237, 45, 11, 148, 91, 112, 156, 47, 68, 229, 216, 56, 238, 98, 41, 243, 225, 192, 0, 0
    };

    unsigned char rhs[96] = {
        199, 130, 235, 52, 44, 219, 5, 195, 71, 154, 54, 121, 3, 11, 111, 160, 86, 212, 189, 66, 235, 236, 240, 242,
        126, 248, 116, 0, 48, 95, 133, 85, 73, 150, 110, 169, 16, 88, 136, 34, 106, 7, 38, 176, 46, 89, 163, 49, 162,
        222, 182, 42, 200, 240, 149, 226, 173, 203, 148, 194, 207, 59, 44, 185, 67, 134, 107, 221, 188, 208, 122, 212,
        200, 42, 227, 3, 23, 59, 31, 37, 91, 64, 69, 196, 74, 195, 24, 5, 165, 25, 101, 215, 45, 92, 1, 0
    };

    unsigned char hash[96] = {
        80, 81, 179, 232, 13, 99, 24, 72, 228, 251, 125, 32, 70, 237, 112, 33, 38, 177, 111, 132, 102, 99, 24, 124, 251,
        129, 134, 216, 47, 118, 33, 252, 65, 59, 238, 39, 13, 39, 62, 58, 164, 220, 43, 52, 33, 95, 89, 238, 148, 11,
        41, 6, 183, 116, 226, 12, 100, 176, 88, 116, 208, 209, 224, 112, 199, 33, 40, 89, 27, 244, 228, 189, 51, 146,
        63, 55, 180, 209, 48, 1, 9, 227, 254, 4, 108, 24, 207, 45, 130, 184, 251, 156, 73, 88, 0, 0
    };

    auto lhs_field = zendoo_deserialize_field(lhs);
    if (lhs_field == NULL) {
        print_error("error: ");
        return;
    }
    auto rhs_field = zendoo_deserialize_field(rhs);
    if (rhs_field == NULL) {
        print_error("error: ");
        return;
    }

    auto expected_hash = zendoo_deserialize_field(hash);
    if (expected_hash == NULL) {
        print_error("error: ");
        return;
    }

    const field_t* hash_input[] = {lhs_field, rhs_field};

    auto actual_hash = zendoo_compute_poseidon_hash(hash_input, 2);
    if (actual_hash == NULL) {
        print_error("error: ");
        return;
    }

    if (!zendoo_field_assert_eq(expected_hash, actual_hash)) {
        std::cout << "Expected hashes to be equal" << std::endl;
        return;
    }

    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);
    zendoo_field_free(expected_hash);
    zendoo_field_free(actual_hash);

    std::cout<< "Hash test...ok" << std::endl;
}

void merkle_test() {

    //Generate random leaves
    int leaves_len = 16;
    const field_t* leaves[leaves_len];
    for (int i = 0; i < leaves_len; i++){
        leaves[i] = zendoo_get_random_field();
    }

    //Create Merkle Tree and get the root
    auto tree = ginger_mt_new(leaves, leaves_len);
    if(tree == NULL){
        print_error("error: ");
        return;
    }
    auto root = ginger_mt_get_root(tree);

    //Verify Merkle Path is ok for each leaf
    for (int i = 0; i < leaves_len; i++) {

        //Create Merkle Path for the i-th leaf
        auto path = ginger_mt_get_merkle_path(leaves[i], i, tree);
        if(path == NULL){
            print_error("error: ");
            return;
        }

        //Verify Merkle Path for the i-th leaf
        if(!ginger_mt_verify_merkle_path(leaves[i], root, path)){
            print_error("error: ");
            return;
        }

        //Free Merkle Path
        ginger_mt_path_free(path);
    }

    //Free the tree
    ginger_mt_free(tree);

    //Free the root
    zendoo_field_free(root);

    //Free all the leaves
    for (int i = 0; i < leaves_len; i++){
        zendoo_field_free((field_t*)leaves[i]);
    }

    std::cout<< "Merkle test...ok" << std::endl;
}

void proof_test() {

    //Deserialize zero knowledge proof

    //Read proof from file
    std::ifstream is ("../test_files/good_proof", std::ifstream::binary);
    is.seekg (0, is.end);
    int length = is.tellg();
    is.seekg (0, is.beg);
    char * proof_bytes = new char [length];
    is.read(proof_bytes,length);
    is.close();

    //Deserialize proof
    auto proof = deserialize_ginger_zk_proof((unsigned char *)proof_bytes);
    if(proof == NULL){
        print_error("error: ");
        return;
    }

    //Deserialize public inputs

    //Read public inputs
    std::ifstream is1 ("../test_files/good_public_inputs", std::ifstream::binary);
    is1.seekg (0, is1.end);
    int length1 = is1.tellg();
    is1.seekg (0, is1.beg);
    char * input_bytes = new char [length];
    is1.read(input_bytes,length1);
    is1.close();

    //Deserialize each field element of the public inputs
    int inputs_len = 4;
    int field_size = zendoo_get_field_size_in_bytes();
    const field_t* public_inputs[inputs_len];
    for(int i = 0; i < inputs_len; i ++){
        public_inputs[i] = zendoo_deserialize_field(&((unsigned char*)input_bytes)[field_size * i]);
    }

    //Verify zkproof
    auto path = (uint8_t*)"../test_files/vk";
    if(!verify_ginger_zk_proof(path, 16, proof, public_inputs, inputs_len)){
        print_error("error: ");
        return;
    }

    //Free proof
    ginger_zk_proof_free(proof);

    //Free public inputs
    for (int i = 0; i < inputs_len; i++){
        zendoo_field_free((field_t*)public_inputs[i]);
    }

    std::cout<< "Zk proof test...ok" << std::endl;
}

int main() {
    field_test();
    pk_test();
    hash_test();
    merkle_test();
    proof_test();
}