#!/usr/bin/env python2

from itertools import chain
import subprocess
import os.path, os, binascii
import random

def compile():
    subprocess.check_call(['make'])

def generate_params(params_dir):
    if os.path.isfile(params_dir + "test_mc_pk") and os.path.isfile(params_dir + "test_mc_vk"):
        return
    args = [];
    args.append("./mcTest")
    args.append("generate")
    args.append(str(params_dir))
    subprocess.check_call(args)

def create_test_proof(verify, proof_path, params_dir, end_epoch_block_hash, prev_end_epoch_block_hash, quality, constant, pks, amounts):
    if not os.path.isfile(params_dir + "test_mc_pk") or not os.path.isfile(params_dir + "test_mc_vk"):
        return
    args = ["./mcTest", "create"]
    if verify:
        args.append("-v")
    args.append(str(proof_path))
    args.append(str(params_dir))
    args += [str(end_epoch_block_hash), str(prev_end_epoch_block_hash), str(quality), str(constant)]
    for (pk, amount) in zip(pks, amounts):
        args.append(str(pk))
        args.append(str(amount))
    subprocess.check_call(args)

def generate_random_field_element_hex():
    return (binascii.b2a_hex(os.urandom(94)) + "0000")

if __name__ == "__main__":
    compile()

    data_dir = os.getcwd() + "/";

    #Generate random pks and amounts
    bt_num = 10
    pks = [binascii.b2a_hex(os.urandom(20)) for i in xrange(bt_num)]
    amounts = [random.randint(0, 100) for i in xrange(bt_num)]

    #Generate vk
    generate_params(data_dir)

    #Assert pk and vk have been generated
    assert os.path.isfile(data_dir + str("test_mc_pk"))
    assert os.path.isfile(data_dir + str("test_mc_vk"))

    #Verify vk is of the expected length
    assert len(open(data_dir + str("test_mc_vk"), "rb").read()) == 1544

    #Create proof
    proof_path = data_dir + str("test_mc_proof")
    create_test_proof(
        True, proof_path, data_dir,
        binascii.b2a_hex(os.urandom(32)), binascii.b2a_hex(os.urandom(32)), 0,
        generate_random_field_element_hex(), pks, amounts
    )

    #Verify proof exists and is of the expected length
    assert os.path.isfile(proof_path)
    assert len(open(proof_path, "rb").read()) == 771
