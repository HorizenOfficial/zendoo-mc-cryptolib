#!/usr/bin/env python2

from itertools import chain
import subprocess
import os.path, os, binascii
import random

def compile():
    '''
       Compile the needed files. This will generate two executables:
       - "getBtMr" that given a list of public keys and amounts, builds a list of
         BackwardTransfer out of them, organizes them in a Merkle Tree and returns
         the Merkle Root;
       - "mcTest" that takes all the needed input to create a MCTestCircuit proof
         and saves the proof and the vk on file.
    '''
    subprocess.check_call(['make'])

def generate_mr_bt(pks, amounts):
    args = ["./getBtMr"]
    for (pk, amount) in zip(pks, amounts):
        args.append(str(pk))
        args.append(str(amount))
    out = subprocess.check_output(args, stderr=subprocess.STDOUT)
    return out

def generate_test_proof_and_vk(end_epoch_block_hash, prev_end_epoch_block_hash, mr_bt, quality, constant, proofdata):
    args = ["./mcTest", str(end_epoch_block_hash), str(prev_end_epoch_block_hash), str(mr_bt), str(quality), str(constant), str(proofdata)]
    subprocess.check_call(args)

if __name__ == "__main__":

    compile()

    #Generate random pks and amounts
    bt_num = 10
    pks = [binascii.b2a_hex(os.urandom(20)) for i in xrange(bt_num)]
    amounts = [random.randint(0, 100) for i in xrange(bt_num)]

    #Generate mr_bt
    mr_bt = generate_mr_bt(pks, amounts)

    #Generate proof and vk
    generate_test_proof_and_vk(
        binascii.b2a_hex(os.urandom(32)), binascii.b2a_hex(os.urandom(32)), mr_bt, 0,
        binascii.b2a_hex(os.urandom(96)), binascii.b2a_hex(os.urandom(96))
    )

    #Verify proof and vk have been generated
    assert os.path.exists("./test_mc_proof")
    assert os.path.exists("./test_mc_vk")

    #Verify proof and vk are valid and of the expected length
    assert len(open("./test_mc_proof", "rb").read()) == 771
    assert len(open("./test_mc_vk", "rb").read()) == 1544


