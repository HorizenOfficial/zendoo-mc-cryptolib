#!/usr/bin/env python2

from itertools import chain
import subprocess
import os.path, os, binascii
import random

NUM_CONSTRAINTS = 1 << 10
SEGMENT_SIZE = 1 << 9
FIELD_SIZE = 32
MC_PK_HASH_SIZE = 20

def generate_params(params_dir, circuit_type, proving_system_type, segment_size = SEGMENT_SIZE, num_constraints = NUM_CONSTRAINTS):
    args = [];
    args.append("./mcTest")
    args.append("generate")
    args.append(str(circuit_type))
    args.append(str(proving_system_type))
    args.append(str(params_dir))
    args.append(str(segment_size))
    args.append(str(num_constraints))
    subprocess.check_call(args)

def cert_proof_test(proof_path, params_dir, ps_type, bt_num, cf_num, zk, with_constant = True, segment_size = SEGMENT_SIZE, num_constraints = NUM_CONSTRAINTS):

    # Setup SNARK pk and vk
    if with_constant:
        generate_params(params_dir, "cert", ps_type, segment_size);
    else:
        generate_params(params_dir, "cert_no_const", ps_type, segment_size);

    # Generate random test data
    sc_id = generate_random_field_element_hex()
    epoch_number = random.randint(0, 10)
    quality = random.randint(0, 100)
    btr_fee = random.randint(0, 1000)
    ft_min_amount = random.randint(0, 5000)
    end_cum_comm_tree_root = generate_random_field_element_hex()
    pks = [binascii.b2a_hex(os.urandom(MC_PK_HASH_SIZE)) for i in xrange(bt_num)]
    amounts = [random.randint(0, 100) for i in xrange(bt_num)]
    custom_fields = [generate_random_field_element_hex() for i in xrange(cf_num)]

    # Generate and verify proof
    circ_type = "cert"
    if not with_constant:
        circ_type = "cert_no_const"

    args = ["./mcTest", "create", circ_type, str(ps_type), "-v"]
    if zk:
        args.append("-zk")
    args.append(str(proof_path))
    args.append(str(params_dir))
    args.append(str(segment_size))
    args += [str(sc_id), str(epoch_number), str(quality)]

    if with_constant:
        constant = generate_random_field_element_hex()
        args.append(str(constant))

    args += [str(end_cum_comm_tree_root), str(btr_fee), str(ft_min_amount), str(num_constraints), str(bt_num)]
    for (pk, amount) in zip(pks, amounts):
        args.append(str(pk))
        args.append(str(amount))

    args.append(str(cf_num))
    for cf in custom_fields:
        args.append(str(cf))

    subprocess.check_call(args)


    # Delete files
    os.remove(proof_path)
    pk_name = "_cert_test_pk"
    vk_name = "_cert_test_vk"
    if not with_constant:
        pk_name = "_cert_no_const_test_pk"
        vk_name = "_cert_no_const_test_vk"
    os.remove(params_dir + str(ps_type) + pk_name)
    os.remove(params_dir + str(ps_type) + vk_name)

def csw_proof_test(proof_path, params_dir, ps_type, zk, cert_data_hash_present, constant = None, segment_size = SEGMENT_SIZE, num_constraints = NUM_CONSTRAINTS):

    # Setup SNARK pk and vk
    if constant is not None:
        generate_params(params_dir, "csw", ps_type, segment_size);
    else:
        generate_params(params_dir, "csw_no_const", ps_type, segment_size);

    # Generate random test data
    amount = random.randint(0, 1000)
    sc_id = generate_random_field_element_hex()
    nullifier = generate_random_field_element_hex()
    mc_pk_hash = binascii.b2a_hex(os.urandom(MC_PK_HASH_SIZE))
    end_cum_comm_tree_root = generate_random_field_element_hex()

    # Generate and verify proof
    circ_type = "csw"
    if constant is None:
        circ_type = "csw_no_const"
    args = ["./mcTest", "create", circ_type, str(ps_type), "-v"]

    if zk:
        args.append("-zk")
    args.append(str(proof_path))
    args.append(str(params_dir))
    args.append(str(segment_size))
    args += [str(amount), str(sc_id), str(nullifier), str(mc_pk_hash), str(end_cum_comm_tree_root), str(num_constraints)]
    if cert_data_hash_present:
        args.append(str(generate_random_field_element_hex()))
    else:
        args.append(str("NO_CERT_DATA_HASH"))
    
    if constant is not None:
        args.append(str(constant))
    
    subprocess.check_call(args)

    # Delete files
    os.remove(proof_path)

    pk_name = "_csw_test_pk"
    vk_name = "_csw_test_vk"
    if constant is None:
        pk_name = "_csw_no_const_test_pk"
        vk_name = "_csw_no_const_test_vk"
    os.remove(params_dir + str(ps_type) + pk_name)
    os.remove(params_dir + str(ps_type) + vk_name)


def generate_random_field_element_hex():
    return (binascii.b2a_hex(os.urandom(FIELD_SIZE - 1)) + "00")

if __name__ == "__main__":

    data_dir = os.getcwd() + "/";

    # # Test certificate proof
    # print('***********Test certificate proof Darlin***********\n')
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, True)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, True)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, False)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, False)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, True)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, True)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, False)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, False)

    # print('***********Test certificate proof Coboundary Marlin***********\n')
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, True)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, True)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, True)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, True)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, False)

    # print('***********Test certificate proof Darlin SS/2***********\n')
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 10, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 10, 0, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 10, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_test_proof"), data_dir, "darlin", 0, 0, False, True, SEGMENT_SIZE/2)

    # print('***********Test certificate proof Coboundary Marlin SS/2***********\n')
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 10, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 10, 0, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, True, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 10, False, True, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_test_proof"), data_dir, "cob_marlin", 0, 0, False, True, SEGMENT_SIZE/2)

    # # Test certificate proof no constant
    # print('***********Test certificate proof w/o constant Darlin***********\n')
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 10, True, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 0, True, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 10, False, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 0, False, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 10, True, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 0, True, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 10, False, False)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 0, False, False)

    # print('***********Test certificate proof w/o constant Coboundary Marlin***********\n')
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 10, True, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 0, True, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 10, False, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 0, False, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 10, True, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 0, True, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 10, False, False)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 0, False, False)

    # print('***********Test certificate proof w/o constant Darlin SS/2***********\n')
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 10, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 0, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 10, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 10, 0, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 10, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 0, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 10, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("darlin_cert_no_const_test_proof"), data_dir, "darlin", 0, 0, False, False, SEGMENT_SIZE/2)

    # print('***********Test certificate proof w/o constant Coboundary Marlin SS/2***********\n')
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 10, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 0, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 10, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 10, 0, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 10, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 0, True, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 10, False, False, SEGMENT_SIZE/2)
    # cert_proof_test(data_dir + str("cob_marlin_cert_no_const_test_proof"), data_dir, "cob_marlin", 0, 0, False, False, SEGMENT_SIZE/2)

    # Test csw proof
    constant = generate_random_field_element_hex()

    print('***********Test csw proof Darlin***********\n')
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", True, True, constant)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", True, False, constant)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", False, True, constant)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", False, False, constant)

    print('***********Test csw proof Coboundary Marlin***********\n')
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", True, True, constant)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", True, False, constant)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", False, True, constant)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", False, False, constant)

    print('***********Test csw proof Darlin SS/2***********\n')
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", True, True, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", True, False, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", False, True, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_test_proof"), data_dir, "darlin", False, False, constant, SEGMENT_SIZE/2)

    print('***********Test csw proof Coboundary Marlin SS/2***********\n')
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", True, True, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", True, False, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", False, True, constant, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_test_proof"), data_dir, "cob_marlin", False, False, constant, SEGMENT_SIZE/2)

    # Test csw proof no constant
    print('***********Test csw proof no const Darlin***********\n')
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", True, True, None)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", True, False, None)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", False, True, None)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", False, False, None)

    print('***********Test csw proof no const Coboundary Marlin***********\n')
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", True, True, None)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", True, False, None)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", False, True, None)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", False, False, None)

    print('***********Test csw proof no const Darlin SS/2***********\n')
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", True, True, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", True, False, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", False, True, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("darlin_csw_no_const_test_proof"), data_dir, "darlin", False, False, None, SEGMENT_SIZE/2)

    print('***********Test csw proof no const Coboundary Marlin SS/2***********\n')
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", True, True, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", True, False, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", False, True, None, SEGMENT_SIZE/2)
    csw_proof_test(data_dir + str("cob_marlin_csw_no_const_test_proof"), data_dir, "cob_marlin", False, False, None, SEGMENT_SIZE/2)
