#include "zendoo_mc.h"
#include "error.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <cassert>
#include <vector>

void print_error(const char *msg) {
    Error err = zendoo_get_last_error();

    fprintf(stderr,
            "%s: %s [%d - %s]\n",
            msg,
            err.msg,
            err.category,
            zendoo_get_category_name(err.category));
}

void error_or(const char* msg){
    if (zendoo_get_last_error().category != 0)
        print_error("error: ");
    else
        std::cout << msg << std::endl;
}

void field_test() {
    std::cout << "Field test" << std::endl;
    //Size is the expected one
    int field_len = zendoo_get_field_size_in_bytes();
    assert(("Unexpected size", field_len == 96));

    auto field = zendoo_get_random_field();

    //Serialize and deserialize and check equality
    unsigned char field_bytes[field_len];
    zendoo_serialize_field(field, field_bytes);

    auto field_deserialized = zendoo_deserialize_field(field_bytes);
    if (field_deserialized == NULL) {
        print_error("error");
        abort();
    }

    assert(("Unexpected deserialized field", zendoo_field_assert_eq(field, field_deserialized)));

    zendoo_field_free(field);
    zendoo_field_free(field_deserialized);

    std::cout<< "...ok" << std::endl;
}


void hash_test() {

    std::cout << "Hash test" << std::endl;

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
        abort();
    }
    auto rhs_field = zendoo_deserialize_field(rhs);
    if (rhs_field == NULL) {
        print_error("error");
        abort();
    }

    auto expected_hash = zendoo_deserialize_field(hash);
    if (expected_hash == NULL) {
        print_error("error");
        abort();
    }

    const field_t* hash_input[] = {lhs_field, rhs_field};

    auto actual_hash = zendoo_compute_poseidon_hash(hash_input, 2);
    if (actual_hash == NULL) {
        print_error("error");
        abort();
    }

    assert(("Expected hashes to be equal", zendoo_field_assert_eq(expected_hash, actual_hash)));

    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);
    zendoo_field_free(expected_hash);
    zendoo_field_free(actual_hash);

    std::cout<< "...ok" << std::endl;
}

void merkle_test() {

    std::cout << "Merkle test" << std::endl;

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
        abort();
    }

    auto root = ginger_mt_get_root(tree);

    //Verify Merkle Path is ok for each leaf
    for (int i = 0; i < leaves_len; i++) {

        //Create Merkle Path for the i-th leaf
        auto path = ginger_mt_get_merkle_path(leaves[i], i, tree);
        if(path == NULL){
            print_error("error");
            abort();
        }

        //Verify Merkle Path for the i-th leaf
        if(!ginger_mt_verify_merkle_path(leaves[i], root, path)){
            error_or("Merkle path not verified");
            abort();
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

    std::cout<< "...ok" << std::endl;
}

void proof_test() {

    std::cout << "Zk proof test" << std::endl;

    //Deserialize zero knowledge proof
    //Read proof from file
    std::ifstream is ("../test_files/sample_proof", std::ifstream::binary);
    is.seekg (0, is.end);
    int length = is.tellg();

    //Check correct length
    assert(("Unexpected size", length == zendoo_get_sc_proof_size_in_bytes()));

    is.seekg (0, is.beg);
    char* proof_bytes = new char [length];
    is.read(proof_bytes,length);
    is.close();

    //Deserialize proof
    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes, true);
    if(proof == NULL){
        print_error("error");
        abort();
    }

    delete[] proof_bytes;

    //Inputs
    unsigned char end_epoch_mc_b_hash[32] = {
        204, 105, 194, 216, 9, 69, 112, 49, 125, 186, 124, 147, 158, 2, 146, 250, 127, 197, 209, 248, 215, 186, 225,
        102, 132, 41, 139, 88, 243, 24, 225, 45
    };

    unsigned char prev_end_epoch_mc_b_hash[32] = {
        77, 107, 100, 149, 66, 133, 64, 12, 129, 179, 101, 205, 224, 222, 215, 10, 94, 82, 185, 91, 180, 22, 32, 249,
        191, 61, 233, 132, 6, 243, 175, 160
    };

    unsigned char constant_bytes[96] = {
        216, 139, 118, 158, 134, 237, 170, 166, 34, 216, 197, 252, 233, 45, 222, 30, 137, 228, 171, 146, 94, 23, 111,
        156, 75, 68, 89, 85, 96, 101, 93, 201, 184, 249, 10, 153, 243, 178, 182, 206, 142, 116, 96, 124, 247, 29, 209,
        33, 52, 217, 110, 145, 19, 27, 198, 93, 55, 184, 137, 54, 172, 83, 73, 255, 0, 57, 85, 59, 73, 168, 63, 79,
        143, 194, 252, 188, 20, 253, 178, 233, 138, 226, 93, 204, 3, 113, 38, 52, 212, 214, 204, 247, 87, 2, 0, 0
    };

    auto constant = zendoo_deserialize_field(constant_bytes);
    if (constant == NULL) {
        print_error("error");
        abort();
    }

    uint64_t quality = 2;

    //Create dummy bt
    size_t bt_list_len = 10;
    const backward_transfer_t bt_list[bt_list_len] = { {0}, 0 };

    //Read vk from file
    std::ifstream is1 ("../test_files/sample_vk", std::ifstream::binary);
    is1.seekg (0, is1.end);
    length = is1.tellg();

    //Check correct length
    assert(("Unexpected size", length == zendoo_get_sc_vk_size_in_bytes()));

    is1.seekg (0, is1.beg);
    char* vk_bytes = new char [length];
    is1.read(vk_bytes,length);
    is1.close();

    //Deserialize vk
    auto vk_from_buffer = zendoo_deserialize_sc_vk((unsigned char*)vk_bytes, true);
    if(vk_from_buffer == NULL){
        print_error("error");
        abort();
    }

    delete[] vk_bytes;

    //Deserialize vk directly from file
    sc_vk_t* vk_from_file = zendoo_deserialize_sc_vk_from_file(
        (path_char_t*)"../test_files/sample_vk",
        23,
        true
    );

    //Check equality
    assert(("Unexpected inequality", zendoo_sc_vk_assert_eq(vk_from_buffer, vk_from_file)));

    //Verify zkproof
    if(!zendoo_verify_sc_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        bt_list,
        bt_list_len,
        quality,
        constant,
        NULL,
        proof,
        vk_from_buffer
    )){
        error_or("Proof not verified");
        abort();
    }

    //Negative test: change quality (for instance) and assert proof failure
    assert((
        "Proof verification should fail",
        !zendoo_verify_sc_proof(
         end_epoch_mc_b_hash,
         prev_end_epoch_mc_b_hash,
         bt_list,
         bt_list_len,
         quality - 1,
         constant,
         NULL,
         proof,
         vk_from_buffer
        )
    ));

    //Free proof
    zendoo_sc_proof_free(proof);
    zendoo_sc_vk_free(vk_from_buffer);
    zendoo_sc_vk_free(vk_from_file);
    zendoo_field_free(constant);

    std::cout<< "...ok" << std::endl;
}

void proof_test_no_bwt() {

    std::cout << "Zk proof no bwt test" << std::endl;

    //Deserialize zero knowledge proof
    //Read proof from file
    std::ifstream is ("../test_files/sample_proof_no_bwt", std::ifstream::binary);
    is.seekg (0, is.end);
    int length = is.tellg();

    //Check correct length
    assert(("Unexpected size", length == zendoo_get_sc_proof_size_in_bytes()));

    is.seekg (0, is.beg);
    char* proof_bytes = new char [length];
    is.read(proof_bytes,length);
    is.close();

    //Deserialize proof
    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes, true);
    if(proof == NULL){
        print_error("error");
        abort();
    }

    delete[] proof_bytes;

    //Inputs
    unsigned char end_epoch_mc_b_hash[32] = {
        200, 100, 76, 16, 225, 149, 155, 252, 61, 173, 237, 209, 206, 10, 20, 247, 200, 41, 133, 21,
        126, 58, 115, 243, 185, 125, 66, 26, 226, 4, 24, 22
    };

    unsigned char prev_end_epoch_mc_b_hash[32] = {
        3, 125, 99, 155, 58, 194, 83, 62, 30, 80, 251, 250, 115, 65, 252, 10, 183, 32, 164, 159,
        238, 237, 100, 96, 227, 163, 108, 249, 193, 81, 182, 77
    };

    unsigned char constant_bytes[96] = {
        50, 121, 119, 120, 18, 130, 90, 56, 28, 219, 172, 115, 102, 55, 207, 79, 69, 68, 3, 24, 114,
        85, 25, 114, 134, 126, 63, 218, 34, 21, 131, 160, 107, 89, 19, 120, 24, 233, 246, 74, 96, 225,
        137, 228, 197, 136, 159, 214, 8, 240, 129, 182, 122, 173, 115, 152, 193, 27, 63, 95, 231, 2,
        128, 224, 63, 184, 130, 233, 147, 254, 252, 151, 210, 191, 227, 0, 46, 38, 123, 35, 56, 231,
        178, 44, 143, 98, 192, 3, 108, 7, 192, 182, 100, 148, 1, 0
    };

    auto constant = zendoo_deserialize_field(constant_bytes);
    if (constant == NULL) {
        print_error("error");
        abort();
    }

    uint64_t quality = 2;

    //Create empty bt_list
    std::vector<backward_transfer_t> bt_list;

    //Read vk from file
    sc_vk_t* vk = zendoo_deserialize_sc_vk_from_file(
        // NOTE: The circuit is the same as the previous one but we regenerate the params for this test
        // for convenience
        (path_char_t*)"../test_files/sample_vk_no_bwt",
        30,
        true
    );

    //Verify zkproof
    if(!zendoo_verify_sc_proof(
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        bt_list.data(),
        0,
        quality,
        constant,
        NULL,
        proof,
        vk
    )){
        error_or("Proof not verified");
        abort();
    }

    //Negative test: change quality (for instance) and assert proof failure
    assert((
        "Proof verification should fail",
        !zendoo_verify_sc_proof(
         end_epoch_mc_b_hash,
         prev_end_epoch_mc_b_hash,
         bt_list.data(),
         0,
         quality - 1,
         constant,
         NULL,
         proof,
         vk
        )
    ));

    //Free proof
    zendoo_sc_proof_free(proof);
    zendoo_sc_vk_free(vk);
    zendoo_field_free(constant);

    std::cout<< "...ok" << std::endl;
}

int main() {
    field_test();
    hash_test();
    merkle_test();
    proof_test();
    proof_test_no_bwt();
}