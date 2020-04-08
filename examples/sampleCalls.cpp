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
    unsigned char field_bytes[field_len];
    if (!zendoo_serialize_field(field, field_bytes)){
        print_error("error");
        return;
    }

    auto field_deserialized = zendoo_deserialize_field(field_bytes);
    if (field_deserialized == NULL) {
        print_error("error");
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

    //Check correct pk deserialization
    unsigned char pk_bytes[193] = {
        74, 157, 68, 149, 157, 108, 203, 45, 83, 153, 115, 12, 34, 48, 43, 61, 94, 145, 101, 119, 126, 110, 124, 242,
        146, 110, 105, 255, 6, 84, 112, 14, 151, 71, 244, 69, 4, 105, 90, 177, 134, 207, 197, 255, 138, 60, 101, 73,
        234, 224, 240, 217, 197, 37, 107, 119, 31, 50, 14, 52, 62, 240, 202, 178, 193, 11, 210, 185, 68, 64, 232, 105,
        153, 170, 17, 97, 33, 49, 140, 35, 123, 226, 8, 45, 179, 59, 244, 50, 225, 214, 98, 245, 6, 139, 1, 0, 185,
        167, 86, 108, 161, 68, 81, 255, 11, 135, 66, 229, 173, 0, 121, 21, 180, 177, 100, 125, 62, 30, 78, 15, 233, 45,
        166, 115, 129, 18, 10, 250, 148, 0, 169, 45, 186, 194, 127, 113, 86, 46, 213, 103, 137, 210, 56, 176, 78, 224,
        163, 186, 100, 77, 237, 226, 90, 61, 129, 191, 243, 44, 218, 189, 9, 83, 44, 79, 246, 156, 121, 111, 250, 217,
        183, 94, 76, 163, 117, 205, 84, 240, 138, 20, 163, 248, 87, 139, 65, 220, 176, 152, 223, 143, 1, 0, 0
    };

    auto pk_deserialized = zendoo_deserialize_pk(pk_bytes);
    if (pk_deserialized == NULL) {
        print_error("error");
        return;
    }

    //Check pk hash commitment consistency
    auto hash_commitment = zendoo_compute_keys_hash_commitment((const pk_t**)&pk_deserialized, 1);
    if(hash_commitment == NULL){
        print_error("error");
        return;
    }

    auto pk_x = zendoo_deserialize_field(&((unsigned char*)pk_bytes)[0]);
    if (pk_x == NULL) {
        print_error("error");
        return;
    }

    auto hash_pk_x = zendoo_compute_poseidon_hash((const field_t**)&pk_x, 1);
    if (hash_pk_x == NULL){
        print_error("error");
        return;
    }

    if(!zendoo_field_assert_eq(hash_commitment, hash_pk_x)) {
        std::cout << "Expected hash_commitment and hash_pk_x to be equal" << std::endl;
        return;
    }

    zendoo_field_free(hash_commitment);
    zendoo_field_free(pk_x);
    zendoo_field_free(hash_pk_x);
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
        53, 2, 235, 12, 255, 18, 125, 167, 223, 32, 245, 103, 38, 74, 43, 73, 254, 189, 174, 137, 20, 90, 195, 107, 202,
        24, 151, 136, 85, 23, 9, 93, 207, 33, 229, 200, 178, 225, 221, 127, 18, 250, 108, 56, 86, 94, 171, 1, 76, 21,
        237, 254, 26, 235, 196, 14, 18, 129, 101, 158, 136, 103, 147, 147, 239, 140, 163, 94, 245, 147, 110, 28, 93,
        231, 66, 7, 111, 11, 202, 99, 146, 211, 117, 143, 224, 99, 183, 108, 157, 200, 119, 169, 180, 148, 0, 0,
    };

    auto lhs_field = zendoo_deserialize_field(lhs);
    if (lhs_field == NULL) {
        print_error("error");
        return;
    }
    auto rhs_field = zendoo_deserialize_field(rhs);
    if (rhs_field == NULL) {
        print_error("error");
        return;
    }

    auto expected_hash = zendoo_deserialize_field(hash);
    if (expected_hash == NULL) {
        print_error("error");
        return;
    }

    const field_t* hash_input[] = {lhs_field, rhs_field};

    auto actual_hash = zendoo_compute_poseidon_hash(hash_input, 2);
    if (actual_hash == NULL) {
        print_error("error");
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
        print_error("error");
        return;
    }

    auto root = ginger_mt_get_root(tree);

    //Verify Merkle Path is ok for each leaf
    for (int i = 0; i < leaves_len; i++) {

        //Create Merkle Path for the i-th leaf
        auto path = ginger_mt_get_merkle_path(leaves[i], i, tree);
        if(path == NULL){
            print_error("error");
            return;
        }

        //Verify Merkle Path for the i-th leaf
        if(!ginger_mt_verify_merkle_path(leaves[i], root, path)){
            print_error("error");
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
    char* proof_bytes = new char [length];
    is.read(proof_bytes,length);
    is.close();

    //Deserialize proof
    auto proof = deserialize_ginger_zk_proof((unsigned char *)proof_bytes);
    if(proof == NULL){
        print_error("error");
        return;
    }

    delete[] proof_bytes;

    //Deserialize public inputs

    //Read public inputs
    std::ifstream is1 ("../test_files/good_public_inputs", std::ifstream::binary);
    is1.seekg (0, is1.end);
    int length1 = is1.tellg();
    is1.seekg (0, is1.beg);
    char* input_bytes = new char [length];
    is1.read(input_bytes,length1);
    is1.close();

    //Deserialize each field element of the public inputs
    int inputs_len = 4;
    int field_size = zendoo_get_field_size_in_bytes();
    const field_t* public_inputs[inputs_len];
    for(int i = 0; i < inputs_len; i ++){
        public_inputs[i] = zendoo_deserialize_field(&((unsigned char*)input_bytes)[field_size * i]);
    }

    delete[] input_bytes;

    //Verify zkproof
    if(!verify_ginger_zk_proof((uint8_t*)"../test_files/vk", 16, proof, public_inputs, inputs_len)){
        print_error("error");
        return;
    }

    //Free public inputs
    for (int i = 0; i < inputs_len; i++){
        zendoo_field_free((field_t*)public_inputs[i]);
    }

    //Negative test: change public inputs and assert proof failure
    for(int i = 0; i < inputs_len; i ++){
        public_inputs[i] = zendoo_get_random_field();
    }

    if(verify_ginger_zk_proof((uint8_t*)"../test_files/vk", 16, proof, public_inputs, inputs_len)){
        std::cout << "Proof verification should fail" << std::endl;
        return;
    }

    //Free public inputs
    for (int i = 0; i < inputs_len; i++){
        zendoo_field_free((field_t*)public_inputs[i]);
    }

    //Free proof
    ginger_zk_proof_free(proof);

    std::cout<< "Zk proof test...ok" << std::endl;
}

int main() {
    field_test();
    pk_test();
    hash_test();
    merkle_test();
    proof_test();
}