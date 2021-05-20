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
    std::cout << "Field: ";
    print_bytes(field_bytes, FIELD_SIZE);
    std::cout << "" << std::endl;
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
        CHECK(ret_code == CctpErrorCode::InvalidValue);

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

void check_root(unsigned char expected_root_bytes[], field_t* actual_root) {
    CctpErrorCode ret_code = CctpErrorCode::OK;
    auto expected_root = zendoo_deserialize_field(expected_root_bytes, &ret_code);
    CHECK(ret_code == CctpErrorCode::OK);
    CHECK(zendoo_field_assert_eq(expected_root, actual_root));
    zendoo_field_free(expected_root);
    zendoo_field_free(actual_root);
}

TEST_CASE("Commitment Tree") {
    CctpErrorCode ret_code = CctpErrorCode::OK;

    // Get commitment tree instance
    auto cmt = zendoo_commitment_tree_create();

    // Test empty tree root
    auto empty_root = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(empty_root != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_empty_root_bytes[FIELD_SIZE] = {
        102, 212, 1, 47, 102, 212, 117, 139, 51, 210, 40, 137, 149, 110, 212, 157,
        149, 193, 18, 216, 145, 99, 127, 83, 230, 240, 0, 196, 108, 233, 101, 13
    };
    check_root(expected_empty_root_bytes, empty_root);

    // Add SCC with random data
    auto sc_id = zendoo_get_field_from_long(1);

    uint64_t amount = 100;
    uint64_t btr_fee = 1000;
    uint64_t ft_min_amount = 5000;
    uint32_t out_idx = 2;
    uint32_t withdrawal_epoch_length = 10;
    uint8_t  mc_btr_request_data_length = 255;

    std::vector<unsigned char> pub_key_vec(FIELD_SIZE, 255);
    auto pub_key = BufferWithSize(pub_key_vec.data(), pub_key_vec.size());

    std::vector<unsigned char> tx_hash_vec(FIELD_SIZE, 255);
    auto tx_hash = BufferWithSize(tx_hash_vec.data(), tx_hash_vec.size());

    std::vector<unsigned char> custom_field_elements_config_vec(5, 1);
    auto custom_field_elements_config = BufferWithSize(custom_field_elements_config_vec.data(), custom_field_elements_config_vec.size());

    size_t custom_bv_elements_config_len = 10;
    const BitVectorElementsConfig custom_bv_elements_config[custom_bv_elements_config_len] = { {2000, 1500} };

    std::vector<unsigned char> custom_creation_data_vec(7, 10);
    auto custom_creation_data = BufferWithSize(custom_creation_data_vec.data(), custom_creation_data_vec.size());

    std::vector<unsigned char> cert_vk_vec(2000, 222);
    auto cert_vk = BufferWithSize(cert_vk_vec.data(), cert_vk_vec.size());

    CHECK(zendoo_commitment_tree_add_scc(
        cmt, sc_id, amount, &pub_key, &tx_hash, out_idx, withdrawal_epoch_length,
        mc_btr_request_data_length, &custom_field_elements_config,
        custom_bv_elements_config, custom_bv_elements_config_len,
        btr_fee, ft_min_amount, &custom_creation_data, NULL,
        &cert_vk, NULL, &ret_code
    ) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add scc
    auto root_after_scc = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_scc != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_scc_bytes[FIELD_SIZE] = {
        166, 173, 139, 78, 105, 234, 68, 33, 65, 9, 233, 183, 187, 254, 31, 32,
        108, 89, 112, 235, 163, 14, 114, 28, 58, 169, 97, 183, 11, 168, 106, 63
    };
    check_root(expected_root_after_scc_bytes, root_after_scc);

    // Add fwt with random data
    CHECK(zendoo_commitment_tree_add_fwt(cmt, sc_id, amount, &pub_key, &tx_hash, out_idx, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add fwt
    auto root_after_fwt = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_fwt != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_fwt_bytes[FIELD_SIZE] = {
        123, 21, 251, 209, 124, 131, 1, 181, 252, 63, 177, 254, 229, 162, 6, 238,
        78, 249, 207, 112, 48, 46, 36, 96, 248, 119, 84, 57, 74, 229, 233, 26
    };
    check_root(expected_root_after_fwt_bytes, root_after_fwt);

    // Add bwtr with random data
    uint64_t sc_fee = 3333;
    auto nullifier = zendoo_get_field_from_long(2);
    auto end_cum_comm_tree_root = zendoo_get_field_from_long(3);

    std::vector<unsigned char> mc_pk_hash_vec(MC_PK_SIZE, 200);
    auto mc_pk_hash = BufferWithSize(mc_pk_hash_vec.data(), mc_pk_hash_vec.size());

    const field_t* sc_req_data[] = {sc_id, nullifier, end_cum_comm_tree_root};
    CHECK(zendoo_commitment_tree_add_bwtr(cmt, sc_id, sc_fee, sc_req_data, 3, &mc_pk_hash, &tx_hash, out_idx, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add bwtr
    auto root_after_bwtr = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_bwtr != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_bwtr_bytes[FIELD_SIZE] = {
        226, 210, 246, 128, 123, 182, 167, 110, 139, 14, 222, 105, 246, 78, 186, 180,
        190, 223, 145, 188, 185, 199, 236, 226, 103, 240, 164, 131, 32, 30, 211, 26
    };
    check_root(expected_root_after_bwtr_bytes, root_after_bwtr);

    // Add csw with random data
    auto new_sc_id = zendoo_get_field_from_long(5); //use new sc_id for csw (it's part of sc_tree_ceased)
    CHECK(zendoo_commitment_tree_add_csw(cmt, new_sc_id, amount, nullifier, &mc_pk_hash, &ret_code) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add csw
    auto root_after_csw = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_csw != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_csw_bytes[FIELD_SIZE] = {
        175, 83, 101, 147, 40, 13, 196, 37, 12, 98, 50, 94, 179, 101, 47, 16, 11,
        147, 119, 27, 52, 188, 128, 101, 210, 146, 56, 209, 51, 128, 158, 34
    };
    check_root(expected_root_after_csw_bytes, root_after_csw);

    // Add cert with random data
    uint32_t epoch_number = 10;
    uint64_t quality = 4444;
    size_t bt_list_len = 10;
    std::vector<backward_transfer_t> bt_list;
    if (bt_list_len != 0) {
        for(int i = 0; i < bt_list_len; i++){
            bt_list.push_back({{255}, 10});
        }
    }
    CHECK(zendoo_commitment_tree_add_cert(
        cmt, sc_id, epoch_number, quality, bt_list.data(), bt_list_len, NULL, 0,
        end_cum_comm_tree_root, btr_fee, ft_min_amount, &ret_code
    ) == true);
    CHECK(ret_code == CctpErrorCode::OK);

    // Test root after add cert
    auto root_after_cert = zendoo_commitment_tree_get_commitment(cmt, &ret_code);
    CHECK(root_after_cert != NULL);
    CHECK(ret_code == CctpErrorCode::OK);

    unsigned char expected_root_after_cert_bytes[FIELD_SIZE] = {
        152, 182, 153, 190, 231, 46, 36, 235, 71, 85, 229, 218, 139, 153, 82, 151,
        109, 110, 163, 4, 67, 104, 185, 240, 112, 49, 168, 58, 63, 76, 27, 26
    };
    check_root(expected_root_after_cert_bytes, root_after_cert);

    zendoo_field_free(sc_id);
    zendoo_field_free(new_sc_id);
    zendoo_field_free(nullifier);
    zendoo_field_free(end_cum_comm_tree_root);
}


TEST_SUITE("Single Proof Verifier") {

    static std::string params_dir = std::string("../examples");
    static size_t params_dir_len = params_dir.size();

    bool initDlogKeys() {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Bootstrap keys
        bool init_result = zendoo_init_dlog_keys(
            ProvingSystem::Darlin,
            1 << 9,
            (path_char_t*)params_dir.c_str(),
            params_dir_len,
            &ret_code
        );
        CHECK(init_result == true);
        CHECK(ret_code == CctpErrorCode::OK);
    }

    void create_verify_cert_proof(
        size_t numBt,
        bool zk,
        std::string proof_path,
        std::string pk_path,
        std::string vk_path
    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto constant = zendoo_get_field_from_long(1);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        uint32_t epoch_number = 10;
        uint64_t quality = 100;
        uint64_t btr_fee = 1000;
        uint64_t ft_min_amount = 5000;

        //Create dummy bt list
        size_t bt_list_len = numBt;
        std::vector<backward_transfer_t> bt_list;
        if (bt_list_len != 0) {
            for(int i = 0; i < bt_list_len; i++){
                bt_list.push_back({{255}, 10});
            }
        }

        // Specify paths
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        CHECK(
            zendoo_create_cert_test_proof(
                zk, constant, epoch_number, quality, bt_list.data(), bt_list_len,
                end_cum_comm_tree_root, btr_fee, ft_min_amount, sc_pk,
                (path_char_t*)proof_path.c_str(), proof_path.size(),
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify proof with correct data

        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Positive verification
        CHECK(
            zendoo_verify_certificate_proof(
                constant, epoch_number, quality, bt_list.data(), bt_list_len,
                NULL, 0, end_cum_comm_tree_root, btr_fee, ft_min_amount,
                sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative verification
        auto wrong_constant = zendoo_get_field_from_long(2);
        CHECK(
            zendoo_verify_certificate_proof(
                wrong_constant, epoch_number, quality, bt_list.data(), bt_list_len,
                NULL, 0, end_cum_comm_tree_root, btr_fee, ft_min_amount,
                sc_proof, sc_vk, &ret_code
            ) == false
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(constant);
        zendoo_field_free(wrong_constant);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    TEST_CASE("Proof Verifier: Cert - Coboundary Marlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
            zendoo_generate_mc_test_params(
                TestCircuitType::Certificate,
                ProvingSystem::CoboundaryMarlin,
                (path_char_t*)params_dir.c_str(),
                params_dir_len,
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/cob_marlin_cert_test_proof");
        auto pk_path = params_dir + std::string("/cob_marlin_cert_test_pk");
        auto vk_path = params_dir + std::string("/cob_marlin_cert_test_vk");

        // Test all cases
        create_verify_cert_proof(10, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(10, false, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, false, proof_path, pk_path, vk_path);

        // Delete files
        remove(pk_path.c_str());
        remove(vk_path.c_str());
    }

    TEST_CASE("Proof Verifier: Cert - Darlin") {
       CctpErrorCode ret_code = CctpErrorCode::OK;

       // Init keys
       initDlogKeys();

       // Generate cert test circuit pk and vk
       CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::Certificate,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
       );
       CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/darlin_cert_test_proof");
        auto pk_path = params_dir + std::string("/darlin_cert_test_pk");
        auto vk_path = params_dir + std::string("/darlin_cert_test_vk");

        // Test all cases
        create_verify_cert_proof(10, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, true, proof_path, pk_path, vk_path);
        create_verify_cert_proof(10, false, proof_path, pk_path, vk_path);
        create_verify_cert_proof(0, false, proof_path, pk_path, vk_path);

       // Delete files
       remove(pk_path.c_str());
       remove(vk_path.c_str());
    }

    void create_verify_csw_proof(
        bool phantomCertDataHash,
        bool zk,
        std::string proof_path,
        std::string pk_path,
        std::string vk_path

    ) {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Generate random data
        auto sc_id = zendoo_get_field_from_long(1);
        auto end_cum_comm_tree_root = zendoo_get_field_from_long(2);
        field_t* cert_data_hash;
        if (phantomCertDataHash) {
            cert_data_hash = zendoo_get_phantom_cert_data_hash();
        } else {
            cert_data_hash = zendoo_get_field_from_long(3);
        }
        uint64_t amount = 100;
        std::vector<unsigned char> mc_pk_hash_vec(MC_PK_SIZE, 255);
        auto mc_pk_hash = BufferWithSize(mc_pk_hash_vec.data(), mc_pk_hash_vec.size());

        // Specify paths
        auto sc_pk = zendoo_deserialize_sc_pk_from_file(
            (path_char_t*)pk_path.c_str(),
            pk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_pk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        CHECK(
            zendoo_create_csw_test_proof(
                zk, amount, sc_id, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_pk, (path_char_t*)proof_path.c_str(), proof_path.size(),
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Verify proof with correct data
        auto sc_proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_proof != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        auto sc_vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path.size(),
            true,
            &ret_code
        );
        CHECK(sc_vk != NULL);
        CHECK(ret_code == CctpErrorCode::OK);

        // Positive verification
        CHECK(
            zendoo_verify_csw_proof(
                amount, sc_id, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_proof, sc_vk, &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Negative verification
        auto wrong_sc_id = zendoo_get_field_from_long(4);
        CHECK(
            zendoo_verify_csw_proof(
                amount, wrong_sc_id, &mc_pk_hash, cert_data_hash, end_cum_comm_tree_root,
                sc_proof, sc_vk, &ret_code
            ) == false
        );
        CHECK(ret_code == CctpErrorCode::OK);

        // Free memory
        zendoo_field_free(sc_id);
        zendoo_field_free(wrong_sc_id);
        zendoo_field_free(cert_data_hash);
        zendoo_field_free(end_cum_comm_tree_root);
        zendoo_sc_pk_free(sc_pk);
        zendoo_sc_vk_free(sc_vk);
        zendoo_sc_proof_free(sc_proof);

        // Destroy proof file
        remove(proof_path.c_str());
    }

    TEST_CASE("Proof Verifier: CSW - Coboundary Marlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
            zendoo_generate_mc_test_params(
                TestCircuitType::CSW,
                ProvingSystem::CoboundaryMarlin,
                (path_char_t*)params_dir.c_str(),
                params_dir_len,
                &ret_code
            ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/cob_marlin_csw_test_proof");
        auto pk_path = params_dir + std::string("/cob_marlin_csw_test_pk");
        auto vk_path = params_dir + std::string("/cob_marlin_csw_test_vk");

        // Test all cases
        create_verify_csw_proof(true, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(true, false, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, false, proof_path, pk_path, vk_path);

        // Delete files
        remove(pk_path.c_str());
        remove(vk_path.c_str());
    }

    TEST_CASE("Proof Verifier: CSW - Darlin") {
        CctpErrorCode ret_code = CctpErrorCode::OK;

        // Init keys
        initDlogKeys();

        // Generate cert test circuit pk and vk
        CHECK(
           zendoo_generate_mc_test_params(
               TestCircuitType::CSW,
               ProvingSystem::Darlin,
               (path_char_t*)params_dir.c_str(),
               params_dir_len,
               &ret_code
           ) == true
        );
        CHECK(ret_code == CctpErrorCode::OK);

        auto proof_path = params_dir + std::string("/darlin_csw_test_proof");
        auto pk_path = params_dir + std::string("/darlin_csw_test_pk");
        auto vk_path = params_dir + std::string("/darlin_csw_test_vk");

        // Test all cases
        create_verify_csw_proof(true, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(true, false, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, true, proof_path, pk_path, vk_path);
        create_verify_csw_proof(false, false, proof_path, pk_path, vk_path);

        // Delete files
        auto ck_g1_path = params_dir + std::string("/ck_g1");
        auto ck_g2_path = params_dir + std::string("/ck_g2");
        remove(pk_path.c_str());
        remove(vk_path.c_str());
        remove(ck_g1_path.c_str());
        remove(ck_g2_path.c_str());
    }
}