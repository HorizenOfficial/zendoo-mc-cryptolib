#include "zendoo_mc.h"
#include "hex_utils.h"
#include <iostream>
#include <cassert>
#include <string>

/*
 *  Usage:
 *
 *  1) ./mcTest "generate" "cert/csw", "darlin/coboundary_marlin", "params_dir"
 *  Generates SNARK pk and vk for a test cert/csw circuit using darlin/coboundary_marlin proving system;
 *  Pre-requisites: DLOG keys should be already loaded in memory;
 *
 *  2) ./mcTest "create" "cert" <"-v"> <"-zk"> "proof_path" "params_dir" "epoch_number" "quality"
 *  "constant" "end_cum_comm_tree_root", "btr_fee", "ft_min_amount",
 *  "pk_dest_0" "amount_0" "pk_dest_1" "amount_1" ... "pk_dest_n" "amount_n"
 *  Generates a TestCertificateProof;
 *
 *  3) ./mcTest "create" "csw" <"-v"> <"-zk"> "proof_path" "params_dir" "amount" "sc_id"
 *  "mc_pk_hash" "end_cum_comm_tree_root", "cert_data_hash",
 *  Generates a TestCSWProof.
 */

void create_verify_test_cert_proof(int argc, char** argv) {
    int arg = 3;
    bool verify = false;
    if (std::string(argv[arg]) == "-v"){
        arg++;
        verify = true;
    }

    bool zk = false;
    if (std::string(argv[arg]) == "-zk") {
        arg++;
        zk = true;
    }

    // Parse inputs
    // Parse paths
    auto proof_path = std::string(argv[arg++]);
    size_t proof_path_len = proof_path.size();

    auto pk_path = std::string(argv[arg]) + std::string("test_cert_pk");
    auto vk_path = std::string(argv[arg++]) + std::string("test_cert_vk");
    size_t pk_path_len = vk_path.size();
    size_t vk_path_len = pk_path_len;

    // Parse epoch number and quality
    uint32_t epoch_number = strtoull(argv[arg++], NULL, 0);
    uint64_t quality = strtoull(argv[arg++], NULL, 0);

    CctpErrorCode ret_code = CctpErrorCode::OK;

    // Parse constant
    assert(IsHex(argv[arg]));
    auto constant = ParseHex(argv[arg++]);
    assert(constant.size() == 32);
    field_t* constant_f = zendoo_deserialize_field(constant.data(), &ret_code);
    assert(constant_f != NULL);
    assert(ret_code == CctpErrorCode::OK);

    // Parse end_cum_comm_tree_root
    assert(IsHex(argv[arg]));
    auto end_cum_comm_tree_root = ParseHex(argv[arg++]);
    assert(end_cum_comm_tree_root.size() == 32);
    field_t* end_cum_comm_tree_root_f = zendoo_deserialize_field(end_cum_comm_tree_root.data(), &ret_code);
    assert(end_cum_comm_tree_root_f != NULL);
    assert(ret_code == CctpErrorCode::OK);

    // Parse btr_fee and ft_min_amount
    uint64_t btr_fee = strtoull(argv[arg++], NULL, 0);
    uint64_t ft_min_amount = strtoull(argv[arg++], NULL, 0);

    // Create bt_list
    // Inputs must be (pk_dest, amount) pairs from which construct backward_transfer_t objects
    assert((argc - arg) % 2 == 0);
    int bt_list_length = (argc - arg)/2;
    assert(bt_list_length >= 0);

    // Parse backward transfer list
    std::vector<backward_transfer_t> bt_list;
    bt_list.reserve(bt_list_length);
    for(int i = 0; i < bt_list_length; i ++){
        backward_transfer_t bt;

        assert(IsHex(argv[arg]));
        auto pk_dest = SetHex(argv[arg++], 20);
        std::copy(pk_dest.begin(), pk_dest.end(), std::begin(bt.pk_dest));

        uint64_t amount = strtoull(argv[arg++], NULL, 0);
        assert(amount >= 0);
        bt.amount = amount;

        bt_list.push_back(bt);
    }

    // Generate proof and vk
    assert(zendoo_create_mc_test_proof(
        zk,
        constant_f,
        epoch_number,
        quality,
        bt_list.data(),
        bt_list_length,
        end_cum_comm_tree_root_f,
        btr_fee,
        ft_min_amount,
        (path_char_t*)pk_path.c_str(),
        pk_path_len,
        (path_char_t*)proof_path.c_str(),
        proof_path_len,
        &ret_code
    ));
    assert(ret_code == CctpErrorCode::OK);

    // If -v was specified we verify the proof just created
    if(verify) {

        // Deserialize proof
        sc_proof_t* proof = zendoo_deserialize_sc_proof_from_file(
            (path_char_t*)proof_path.c_str(),
            proof_path_len,
            false,
            &ret_code,
        );
        assert(proof != NULL);
        assert(ret_code == CctpErrorCode::OK);

        // Deserialize vk
        sc_vk_t* vk = zendoo_deserialize_sc_vk_from_file(
            (path_char_t*)vk_path.c_str(),
            vk_path_len,
            false,
            &ret_code
        );
        assert(vk != NULL);
        assert(ret_code == CctpErrorCode::OK);

        // Verify proof
        assert(zendoo_verify_sc_proof(
            constant_f,
            epoch_number,
            quality,
            bt_list.data(),
            bt_list_length,
            NULL,
            0,
            end_cum_comm_tree_root_f,
            btr_fee,
            ft_min_amount,
            proof,
            vk,
            &ret_code
        ));

        zendoo_sc_proof_free(proof);
        zendoo_sc_vk_free(vk);
    }

    zendoo_field_free(constant_f);
    zendoo_field_free(end_cum_comm_tree_root_f);
}

void create_verify_test_csw_proof(int argc, char** argv) {
    int arg = 3;
    bool verify = false;
    if (std::string(argv[arg]) == "-v"){
        arg++;
        verify = true;
    }

    bool zk = false;
    if (std::string(argv[arg]) == "-zk") {
        arg++;
        zk = true;
    }

    // Parse inputs
    // Parse paths
    auto proof_path = std::string(argv[arg++]);
    size_t proof_path_len = proof_path.size();

    auto pk_path = std::string(argv[arg]) + std::string("test_cert_pk");
    auto vk_path = std::string(argv[arg++]) + std::string("test_cert_vk");
    size_t pk_path_len = vk_path.size();
    size_t vk_path_len = pk_path_len;
}

void create_verify(int argc, char** argv)
{
    auto circ_type_raw = std::string(argv[2]);
    if (circ_type_raw == "cert") {
        create_verify_test_cert_proof(argc, argv);
    } else if (circ_type_raw == "csw") {
        create_verify_test_csw_proof(argc, argv);
    } else {
        abort(); // Invalid TestCircuitType
    }
}

void generate(char** argv)
{
    // Get TestCircuitType
    auto circ_type_raw = std::string(argv[2]);
    TestCircuitType circ_type;
    if (circ_type_raw == "cert") {
        circ_type = TestCircuitType::Certificate;
    } else if (circ_type_raw == "csw") {
        circ_type = TestCircuitType::CSW;
    } else {
        abort(); // Invalid TestCircuitType
    }

    // Get ProvingSystemType
    auto ps_type_raw = std::string(argv[3]);
    ProvingSystem ps_type;
    if (ps_type_raw == "darlin") {
        ps_type = ProvingSystem::Darlin;
    } else if (ps_type_raw == "coboundary_marlin") {
        ps_type = ProvingSystem::CoboundaryMarlin;
    } else {
        abort(); // Invalid ProvingSystemType
    }

    // Get Path
    auto path = std::string(argv[4]);

    // Generate proving and verifying key
    CctpErrorCode ret_code = CctpErrorCode::OK;
    assert(zendoo_generate_mc_test_params(circ_type, ps_type, (path_char_t*)path.c_str(), path.size()), &ret_code);
    assert(ret_code = CctpErrorCode::OK);
}


int main(int argc, char** argv)
{
    if(std::string(argv[1]) == "generate") {
        assert(argc == 5);
        generate(argv);
    } else if (std::string(argv[1]) == "create"){
        assert(argc > 7);
        create_verify(argc, argv);
    } else {
        abort();
    }
}