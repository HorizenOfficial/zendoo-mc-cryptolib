#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "zendoo_mc.h"
#include "doctest.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <cassert>
#include <vector>

void print_bytes(unsigned char bytes[], size_t len){
    for(int i = 0; i < len; i++){
        std::cout << (int)bytes[i];
        std::cout << ", ";
    }
}

void print_field(field_t* field) {
    CctpErrorCode ret_code = CctpErrorCode::OK;
    unsigned char field_bytes[FIELD_SIZE];
    zendoo_serialize_field(field, field_bytes, &ret_code);
    print_bytes(field_bytes, FIELD_SIZE);
}

TEST_SUITE("Field Element") {

    TEST_CASE("Field Size") {
        int field_len = zendoo_get_field_size_in_bytes();
        CHECK(field_len == FIELD_SIZE);
    }

    TEST_CASE("Positive serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Check correct serialization
        auto field = zendoo_get_random_field();

        //Serialize and deserialize and check equality
        unsigned char field_bytes[FIELD_SIZE];
        zendoo_serialize_field(field, field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check correct deserialization
        auto field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check equality
        CHECK(zendoo_field_assert_eq(field, field_deserialized));

        zendoo_field_free(field);
        zendoo_field_free(field_deserialized);
    }

    TEST_CASE("Negative serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        //Serialize and deserialize and check equality
        unsigned char field_bytes[FIELD_SIZE] = {
            64, 192, 222, 36, 97, 22, 129, 41, 101, 218, 34, 193, 41, 200, 74, 248,
            126, 226, 209, 85, 85, 50, 64, 27, 23, 69, 240, 210, 79, 85, 196, 3
        };

        // Check correct deserialization
        auto correct_field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Modify a byte of field_bytes and deserialize
        field_bytes[0] = 0;
        auto wrong_field_deserialized = zendoo_deserialize_field(field_bytes, &ret_code);

        // Check equality
        CHECK_FALSE(zendoo_field_assert_eq(correct_field_deserialized, wrong_field_deserialized));

        // Free memory
        zendoo_field_free(correct_field_deserialized);
        zendoo_field_free(wrong_field_deserialized);
    }

    TEST_CASE("Edge cases serialize/deserialize"){
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Attempt to deserialize a field element over the modulus
        unsigned char over_the_modulus_fe[FIELD_SIZE] = {
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255
        };
        auto field_deserialized = zendoo_deserialize_field(over_the_modulus_fe, &ret_code);
        CHECK(field_deserialized == NULL);
        CHECK(ret_code == CctpErrorCode::InvalidBufferData);

        zendoo_field_free(field_deserialized);
    }
}

TEST_SUITE("Poseidon Hash") {

    static const unsigned char expected_result_bytes[FIELD_SIZE] = {
        254, 126, 175, 176, 130, 2, 161, 183, 90, 48, 41, 150, 100, 148, 142, 37,
        122, 246, 6, 134, 190, 158, 5, 195, 112, 148, 148, 144, 106, 91, 234, 5
    };

    TEST_CASE("Constant Length Poseidon Hash") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init digest
        auto digest = ZendooPoseidonHashConstantLength(2, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Trying to finalize without having reached the
        // specified input size will cause an error
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one
        auto expected_result = zendoo_deserialize_field(expected_result_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // Update once and more and assert that trying to finalize with more
        // inputs than the ones specified at creation will result in an error.
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }

    TEST_CASE("Variable Length Poseidon Hash mod rate") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init digest
        auto digest = ZendooPoseidonHashVariableLength(true, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Trying to finalize with an input size non mod rate
        // will result in an error
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one.
        // Result is also the same of the constant length poseidon hash
        // (no unnecessary padding is added)
        auto expected_result = zendoo_deserialize_field(expected_result_bytes, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // Update once and more and assert that trying to finalize
        // with an input non mod rate will result in an error
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after == NULL);
        CHECK(ret_code == CctpErrorCode::HashingError);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }

    TEST_CASE("Variable Length Poseidon Hash NON mod rate") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        unsigned char expected_result_bytes_variable_length[FIELD_SIZE] = {
            212, 129, 183, 174, 117, 46, 61, 128, 124, 74, 158, 233, 177, 251, 225, 0,
            99, 148, 140, 105, 239, 1, 217, 66, 106, 133, 62, 197, 131, 215, 206, 28
        };

        // Init digest
        auto digest = ZendooPoseidonHashVariableLength(false, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        //Update with 1 field element
        auto lhs = zendoo_get_field_from_long(1);
        digest.update(lhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // It's possible to finalize in any moment (padding will be performed)
        auto result_before = digest.finalize(&ret_code);
        CHECK(result_before != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Update with 1 field element
        auto rhs = zendoo_get_field_from_long(2);
        digest.update(rhs, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Finalize hash
        auto result = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Check result is equal to the expected one.
        auto expected_result = zendoo_deserialize_field(expected_result_bytes_variable_length, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, expected_result));

        // Finalize is idempotent
        auto result_copy = digest.finalize(&ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
        CHECK(zendoo_field_assert_eq(result, result_copy));

        // It's possible to finalize in any moment (padding will be performed)
        auto additional_input = zendoo_get_field_from_long(3);
        digest.update(additional_input, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        auto result_after = digest.finalize(&ret_code);
        CHECK(result_after != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(lhs);
        zendoo_field_free(rhs);
        zendoo_field_free(result_before);
        zendoo_field_free(result);
        zendoo_field_free(expected_result);
        zendoo_field_free(result_copy);
        zendoo_field_free(result_after);
        zendoo_field_free(additional_input);

        // Once out of scope the destructor of ZendooPoseidonHash will automatically free the memory Rust-side
        // for digest
    }
}

TEST_CASE("Merkle Tree") {
    size_t height = 5;
    CctpErrorCode ret_code = CctpErrorCode::OK;

    // Deserialize root
    unsigned char expected_root_bytes[FIELD_SIZE] = {
        113, 174, 41, 1, 227, 14, 47, 27, 44, 172, 21, 18, 63, 182, 174, 162, 239, 251,
        93, 88, 43, 221, 235, 253, 30, 110, 180, 114, 134, 192, 15, 20
    };
    auto expected_root = zendoo_deserialize_field(expected_root_bytes, &ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

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
        tree.append(leaves[i], &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);
    }

    // Adding more leaves than the tree size should result in an error
    tree.append(leaves[0], &ret_code);
    CHECK(ret_code == CctpErrorCode::MerkleTreeError);

    // Asking for the root of a non-finalized tree should result in an error
    auto null_root = tree.root(&ret_code);
    CHECK(null_root == NULL);
    CHECK(ret_code == CctpErrorCode::MerkleRootBuildError);

    // Asking for a merkle path  of a non-finalized tree should result in an error
    auto path = tree.get_merkle_path(0, &ret_code);
    CHECK(path == NULL);
    CHECK(ret_code == CctpErrorCode::MerkleTreeError);

    // Finalize tree
    tree.finalize_in_place(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    // Compute root and assert equality with expected one
    auto root = tree.root(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);
    CHECK(zendoo_field_assert_eq(root, expected_root));

    // It is the same by calling finalize()
    auto tree_copy = tree.finalize(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    auto root_copy = tree_copy.root(&ret_code);
    CHECK(ret_code == CctpErrorCode::OK);

    CHECK(zendoo_field_assert_eq(root_copy, root));

    auto wrong_root = zendoo_get_random_field();

    // Test Merkle Paths
    for (int i = 0; i < leaves_len; i++) {

        // Get Merkle Path
        auto path = tree.get_merkle_path(i, &ret_code);
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify Merkle Path
        CHECK(zendoo_verify_ginger_merkle_path(path, height, (field_t*)leaves[i], root, &ret_code));
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative test: verify MerklePath for a wrong root and assert failure
        CHECK_FALSE(zendoo_verify_ginger_merkle_path(path, height, (field_t*)leaves[i], wrong_root, &ret_code));
        CHECK(ret_code == CctpErrorCode::OK);

        zendoo_free_ginger_merkle_path(path);
    }

    // Free memory
    for (int i = 0; i < leaves_len; i++){
        zendoo_field_free((field_t*)leaves[i]);
    }
    zendoo_field_free(root);
    zendoo_field_free(root_copy);
    zendoo_field_free(expected_root);
    zendoo_field_free(wrong_root);

    // Once out of scope the destructor of ZendooGingerMerkleTree will automatically free
    // the memory Rust-side for tree and tree_copy
}


//
//void proof_test() {
//
//    std::cout << "Zk proof test" << std::endl;
//
//    //Deserialize zero knowledge proof
//    //Read proof from file
//    std::ifstream is ("../test_files/sample_proof", std::ifstream::binary);
//    is.seekg (0, is.end);
//    int length = is.tellg();
//
//    //Check correct length
//    assert(("Unexpected size", length == zendoo_get_sc_proof_size_in_bytes()));
//
//    is.seekg (0, is.beg);
//    char* proof_bytes = new char [length];
//    is.read(proof_bytes,length);
//    is.close();
//
//    //Deserialize proof
//    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes, true);
//    if(proof == NULL){
//        print_error("error");
//        abort();
//    }
//
//    delete[] proof_bytes;
//
//    //Inputs
//    unsigned char end_epoch_mc_b_hash[32] = {
//        157, 219, 85, 159, 75, 56, 146, 21, 107, 239, 76, 31, 208, 213, 230, 24, 44, 74, 250, 66, 71, 23, 106, 4, 138,
//        157, 28, 43, 158, 39, 152, 91
//    };
//
//    unsigned char prev_end_epoch_mc_b_hash[32] = {
//        74, 229, 219, 59, 25, 231, 227, 68, 3, 118, 194, 58, 99, 219, 112, 39, 73, 202, 238, 140, 114, 144, 253, 32,
//        237, 117, 117, 60, 200, 70, 187, 171
//    };
//
//    unsigned char constant_bytes[96] = {
//        234, 144, 148, 15, 127, 44, 243, 131, 152, 238, 209, 246, 126, 175, 154, 42, 208, 215, 180, 233, 20, 153, 7, 10,
//        180, 78, 89, 9, 9, 160, 1, 42, 91, 202, 221, 104, 241, 231, 8, 59, 174, 159, 27, 108, 74, 80, 118, 192, 127, 238,
//        216, 167, 72, 15, 61, 97, 121, 13, 48, 143, 255, 165, 228, 6, 121, 210, 112, 228, 161, 214, 233, 137, 108, 184,
//        80, 27, 213, 72, 110, 7, 200, 194, 23, 95, 102, 236, 181, 230, 139, 215, 104, 22, 214, 70, 0, 0
//    };
//
//    auto constant = zendoo_deserialize_field(constant_bytes);
//    if (constant == NULL) {
//        print_error("error");
//        abort();
//    }
//
//    uint64_t quality = 2;
//
//    //Create dummy bt
//    size_t bt_list_len = 10;
//    const backward_transfer_t bt_list[bt_list_len] = { {0}, 0 };
//
//    //Read vk from file
//    std::ifstream is1 ("../test_files/sample_vk", std::ifstream::binary);
//    is1.seekg (0, is1.end);
//    length = is1.tellg();
//
//    //Check correct length
//    assert(("Unexpected size", length == zendoo_get_sc_vk_size_in_bytes()));
//
//    is1.seekg (0, is1.beg);
//    char* vk_bytes = new char [length];
//    is1.read(vk_bytes,length);
//    is1.close();
//
//    //Deserialize vk
//    auto vk_from_buffer = zendoo_deserialize_sc_vk((unsigned char*)vk_bytes, true);
//    if(vk_from_buffer == NULL){
//        print_error("error");
//        abort();
//    }
//
//    delete[] vk_bytes;
//
//    //Deserialize vk directly from file
//    sc_vk_t* vk_from_file = zendoo_deserialize_sc_vk_from_file(
//        (path_char_t*)"../test_files/sample_vk",
//        23,
//        true
//    );
//
//    //Check equality
//    assert(("Unexpected inequality", zendoo_sc_vk_assert_eq(vk_from_buffer, vk_from_file)));
//
//    //Verify zkproof
//    if(!zendoo_verify_sc_proof(
//        end_epoch_mc_b_hash,
//        prev_end_epoch_mc_b_hash,
//        bt_list,
//        bt_list_len,
//        quality,
//        constant,
//        NULL,
//        proof,
//        vk_from_buffer
//    )){
//        error_or("Proof not verified");
//        abort();
//    }
//
//    //Negative test: change quality (for instance) and assert proof failure
//    assert((
//        "Proof verification should fail",
//        !zendoo_verify_sc_proof(
//         end_epoch_mc_b_hash,
//         prev_end_epoch_mc_b_hash,
//         bt_list,
//         bt_list_len,
//         quality - 1,
//         constant,
//         NULL,
//         proof,
//         vk_from_buffer
//        )
//    ));
//
//    //Free proof
//    zendoo_sc_proof_free(proof);
//    zendoo_sc_vk_free(vk_from_buffer);
//    zendoo_sc_vk_free(vk_from_file);
//    zendoo_field_free(constant);
//
//    std::cout<< "...ok" << std::endl;
//}
//
//void proof_test_no_bwt() {
//
//    std::cout << "Zk proof no bwt test" << std::endl;
//
//    //Deserialize zero knowledge proof
//    //Read proof from file
//    std::ifstream is ("../test_files/sample_proof_no_bwt", std::ifstream::binary);
//    is.seekg (0, is.end);
//    int length = is.tellg();
//
//    //Check correct length
//    assert(("Unexpected size", length == zendoo_get_sc_proof_size_in_bytes()));
//
//    is.seekg (0, is.beg);
//    char* proof_bytes = new char [length];
//    is.read(proof_bytes,length);
//    is.close();
//
//    //Deserialize proof
//    auto proof = zendoo_deserialize_sc_proof((unsigned char *)proof_bytes, true);
//    if(proof == NULL){
//        print_error("error");
//        abort();
//    }
//
//    delete[] proof_bytes;
//
//    //Inputs
//    unsigned char end_epoch_mc_b_hash[32] = {
//        8, 57, 79, 205, 58, 30, 190, 170, 144, 137, 231, 236, 172, 54, 173, 50, 69, 208, 163, 134, 201, 131, 129, 223,
//        143, 76, 119, 48, 95, 6, 141, 17
//    };
//
//    unsigned char prev_end_epoch_mc_b_hash[32] = {
//        172, 64, 135, 162, 30, 208, 207, 7, 107, 205, 4, 141, 230, 6, 119, 131, 112, 98, 170, 234, 70, 66, 95, 11, 159,
//        178, 50, 37, 95, 187, 147, 1
//    };
//
//    unsigned char constant_bytes[96] = {
//        53, 15, 18, 36, 121, 179, 90, 14, 215, 218, 231, 181, 9, 186, 122, 78, 227, 142, 190, 43, 134, 218, 178, 160,
//        251, 246, 207, 130, 247, 53, 246, 68, 251, 126, 22, 250, 0, 135, 243, 13, 97, 76, 166, 142, 143, 19, 69, 66,
//        225, 142, 210, 176, 253, 197, 145, 68, 142, 4, 96, 91, 23, 39, 56, 43, 96, 115, 57, 59, 34, 62, 156, 221, 27,
//        174, 134, 170, 26, 86, 112, 176, 126, 207, 29, 213, 99, 3, 183, 43, 191, 43, 211, 110, 177, 152, 0, 0
//    };
//
//    auto constant = zendoo_deserialize_field(constant_bytes);
//    if (constant == NULL) {
//        print_error("error");
//        abort();
//    }
//
//    uint64_t quality = 2;
//
//    //Create empty bt_list
//    std::vector<backward_transfer_t> bt_list;
//
//    //Read vk from file
//    sc_vk_t* vk = zendoo_deserialize_sc_vk_from_file(
//        // NOTE: The circuit is the same as the previous one but we regenerate the params for this test
//        // for convenience
//        (path_char_t*)"../test_files/sample_vk_no_bwt",
//        30,
//        true
//    );
//
//    //Verify zkproof
//    if(!zendoo_verify_sc_proof(
//        end_epoch_mc_b_hash,
//        prev_end_epoch_mc_b_hash,
//        bt_list.data(),
//        0,
//        quality,
//        constant,
//        NULL,
//        proof,
//        vk
//    )){
//        error_or("Proof not verified");
//        abort();
//    }
//
//    //Negative test: change quality (for instance) and assert proof failure
//    assert((
//        "Proof verification should fail",
//        !zendoo_verify_sc_proof(
//         end_epoch_mc_b_hash,
//         prev_end_epoch_mc_b_hash,
//         bt_list.data(),
//         0,
//         quality - 1,
//         constant,
//         NULL,
//         proof,
//         vk
//        )
//    ));
//
//    //Free proof
//    zendoo_sc_proof_free(proof);
//    zendoo_sc_vk_free(vk);
//    zendoo_field_free(constant);
//
//    std::cout<< "...ok" << std::endl;
//}
//
//int main() {
//    field_test();
//    hash_test();
//    merkle_test();
//    proof_test();
//    proof_test_no_bwt();
//}