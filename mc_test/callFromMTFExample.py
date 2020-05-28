#!/usr/bin/env python2

from itertools import chain
import subprocess
import os.path, os, binascii
import random

def compile():
    subprocess.check_call(['make'])

def generate_params():
    args = [];
    args.append("./mcTest")
    args.append("generate")
    subprocess.check_call(args)

def create_test_proof(verify, end_epoch_block_hash, prev_end_epoch_block_hash, quality, constant, pks, amounts):
    args = ["./mcTest", "create"]
    if verify:
        args.append("-v")
    args += [str(end_epoch_block_hash), str(prev_end_epoch_block_hash), str(quality), str(constant)]
    for (pk, amount) in zip(pks, amounts):
        args.append(str(pk))
        args.append(str(amount))
    subprocess.check_call(args)

def generate_random_field_element_hex():
    return (binascii.b2a_hex(os.urandom(94)) + "0000")

if __name__ == "__main__":
    compile()

    #Generate random pks and amounts
    bt_num = 10
    pks = [binascii.b2a_hex(os.urandom(20)) for i in xrange(bt_num)]
    amounts = [random.randint(0, 100) for i in xrange(bt_num)]

    #Generate vk
    generate_params()

    #Create proof
    create_test_proof(
        True,
        binascii.b2a_hex(os.urandom(32)), binascii.b2a_hex(os.urandom(32)), 0,
        generate_random_field_element_hex(), pks, amounts
    )

    #Verify proof and vk have been generated
    assert os.path.exists("./test_mc_proof")
    assert os.path.exists("./test_mc_vk")

    #Verify proof and vk are valid and of the expected length
    assert len(open("./test_mc_proof", "rb").read()) == 771
    assert len(open("./test_mc_vk", "rb").read()) == 1544


