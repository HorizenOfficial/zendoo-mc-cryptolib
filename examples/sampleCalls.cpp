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

    auto digest = ZendooPoseidonHash();

    digest.update(lhs_field);

    auto temp_hash = digest.finalize();
    digest.update(rhs_field); // Call to finalize keeps the state

    auto actual_hash = digest.finalize();
    assert(("Expected hashes to be equal", zendoo_field_assert_eq(actual_hash, expected_hash)));
    zendoo_field_free(actual_hash);

    auto actual_hash_2 = digest.finalize(); // finalize() is idempotent
    assert(("Expected hashes to be equal", zendoo_field_assert_eq(actual_hash_2, expected_hash)));
    zendoo_field_free(actual_hash_2);

    zendoo_field_free(expected_hash);
    zendoo_field_free(temp_hash);
    zendoo_field_free(lhs_field);
    zendoo_field_free(rhs_field);

    std::cout<< "...ok" << std::endl;

    // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
    // for digest
}

void merkle_test() {

    std::cout << "Merkle test" << std::endl;

    size_t height = 5;

    // Deserialize root
    unsigned char expected_root_bytes[96] = {
        192, 138, 102, 85, 151, 8, 139, 184, 209, 249, 171, 182, 227, 80, 52, 215, 32, 37, 145, 166,
        74, 136, 40, 200, 213, 72, 124, 101, 91, 235, 114, 0, 147, 61, 180, 29, 183, 111, 247, 2,
        169, 12, 179, 173, 87, 88, 187, 229, 26, 139, 80, 228, 125, 246, 145, 141, 43, 19, 148, 94,
        190, 140, 20, 123, 208, 132, 48, 243, 14, 2, 48, 106, 100, 13, 41, 254, 129, 225, 168, 23,
        72, 215, 207, 255, 98, 156, 102, 215, 201, 158, 10, 123, 107, 238, 0, 0
    };
    auto expected_root = zendoo_deserialize_field(expected_root_bytes);
    if (expected_root == NULL) {
        print_error("error");
        abort();
    }

    //Generate leaves
    int leaves_len = 32;
    const field_t* leaves[leaves_len];
    for (int i = 0; i < leaves_len; i++){
        leaves[i] = zendoo_get_field_from_long(i);
    }

    // Initialize tree
    auto tree = ZendooGingerMerkleTree(height, leaves_len);

    // Add leaves to tree
    for (int i = 0; i < leaves_len; i++){
        tree.append(leaves[i]);
    }

    // Finalize tree
    tree.finalize_in_place();

    // Compute root and assert equality with expected one
    auto root = tree.root();
    assert(("Expected roots to be equal", zendoo_field_assert_eq(root, expected_root)));

    // It is the same by calling finalize()
    auto tree_copy = tree.finalize();
    auto root_copy = tree_copy.root();
    assert(("Expected roots to be equal", zendoo_field_assert_eq(root_copy, expected_root)));

    // Test Merkle Paths
    for (int i = 0; i < leaves_len; i++) {
        auto path = tree.get_merkle_path(i);
        assert(("Merkle Path must be verified", zendoo_verify_ginger_merkle_path(path, height, (field_t*)leaves[i], root)));
        zendoo_free_ginger_merkle_path(path);
    }

    // Free memory
    zendoo_field_free(expected_root);
    for (int i = 0; i < leaves_len; i++){
        zendoo_field_free((field_t*)leaves[i]);
    }
    zendoo_field_free(root);
    zendoo_field_free(root_copy);

    std::cout<< "...ok" << std::endl;

    // Once out of scope, the destructor of ZendooGingerMerkleTree will
    // free the memory Rust-side for tree and tree_copy.
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
    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes);
    if(proof == NULL){
        print_error("error");
        abort();
    }

    delete[] proof_bytes;

    //Inputs
    unsigned char end_epoch_mc_b_hash[32] = {
        157, 219, 85, 159, 75, 56, 146, 21, 107, 239, 76, 31, 208, 213, 230, 24, 44, 74, 250, 66, 71, 23, 106, 4, 138,
        157, 28, 43, 158, 39, 152, 91
    };

    unsigned char prev_end_epoch_mc_b_hash[32] = {
        74, 229, 219, 59, 25, 231, 227, 68, 3, 118, 194, 58, 99, 219, 112, 39, 73, 202, 238, 140, 114, 144, 253, 32,
        237, 117, 117, 60, 200, 70, 187, 171
    };

    unsigned char constant_bytes[96] = {
        234, 144, 148, 15, 127, 44, 243, 131, 152, 238, 209, 246, 126, 175, 154, 42, 208, 215, 180, 233, 20, 153, 7, 10,
        180, 78, 89, 9, 9, 160, 1, 42, 91, 202, 221, 104, 241, 231, 8, 59, 174, 159, 27, 108, 74, 80, 118, 192, 127, 238,
        216, 167, 72, 15, 61, 97, 121, 13, 48, 143, 255, 165, 228, 6, 121, 210, 112, 228, 161, 214, 233, 137, 108, 184,
        80, 27, 213, 72, 110, 7, 200, 194, 23, 95, 102, 236, 181, 230, 139, 215, 104, 22, 214, 70, 0, 0
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
    auto vk_from_buffer = zendoo_deserialize_sc_vk((unsigned char*)vk_bytes);
    if(vk_from_buffer == NULL){
        print_error("error");
        abort();
    }

    delete[] vk_bytes;

    //Deserialize vk directly from file
    sc_vk_t* vk_from_file = zendoo_deserialize_sc_vk_from_file(
        (path_char_t*)"../test_files/sample_vk",
        23
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
    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes);
    if(proof == NULL){
        print_error("error");
        abort();
    }

    delete[] proof_bytes;

    //Inputs
    unsigned char end_epoch_mc_b_hash[32] = {
        8, 57, 79, 205, 58, 30, 190, 170, 144, 137, 231, 236, 172, 54, 173, 50, 69, 208, 163, 134, 201, 131, 129, 223,
        143, 76, 119, 48, 95, 6, 141, 17
    };

    unsigned char prev_end_epoch_mc_b_hash[32] = {
        172, 64, 135, 162, 30, 208, 207, 7, 107, 205, 4, 141, 230, 6, 119, 131, 112, 98, 170, 234, 70, 66, 95, 11, 159,
        178, 50, 37, 95, 187, 147, 1
    };

    unsigned char constant_bytes[96] = {
        53, 15, 18, 36, 121, 179, 90, 14, 215, 218, 231, 181, 9, 186, 122, 78, 227, 142, 190, 43, 134, 218, 178, 160,
        251, 246, 207, 130, 247, 53, 246, 68, 251, 126, 22, 250, 0, 135, 243, 13, 97, 76, 166, 142, 143, 19, 69, 66,
        225, 142, 210, 176, 253, 197, 145, 68, 142, 4, 96, 91, 23, 39, 56, 43, 96, 115, 57, 59, 34, 62, 156, 221, 27,
        174, 134, 170, 26, 86, 112, 176, 126, 207, 29, 213, 99, 3, 183, 43, 191, 43, 211, 110, 177, 152, 0, 0
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
        (path_char_t*)"../test_files/sample_vk_no_bwt",
        30
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