import rlp

from viper import compiler
from ethereum.slogging import get_logger
from ethereum import utils
from ethereum.tools import tester



test_account_proof_code = """
pos0: bytes32
pos1: public(num[num])
pos2: num[num]

def set_pos1(k: num, v: num):
    self.pos1[k] = v

def set_pos2(k: num, v: num):
    self.pos2[k] = v
"""


def test_storage_key():
    tester.languages['viper'] = compiler.Compiler()
    c = tester.Chain()


    test_account_proof_contract = c.contract(test_account_proof_code, language='viper')
    test_account_proof_contract.set_pos1(1, 3)
    # assert test_account_proof_contract.get_pos1(1) == 3