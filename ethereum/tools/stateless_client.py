import rlp

from ethereum.utils import sha3, encode_hex
from ethereum import trie


def get_merkle_proof(db, root, value):
    """Get the merkle proof of a given value in trie
    
    value must exist in trie or exception will be thrown

    returns a list of nodes starting from root to leaf node
    """
    assert db and root and value
    # print("key:", value)
    key = sha3(value)
    # make sure the value exist in the trie 
    assert trie._get(db, root, trie.encode_bin(key))
    # print("value:", trie._get(db, root, trie.encode_bin(key)))
    proof = trie._get_branch(db, root, trie.encode_bin(key))
    # print("proof:", proof)
    # print("")
    return proof

def verify_merkle_proof(branch, root, value):
    """Verify if a given value exist in trie

    returns true or false
    """
    assert branch and root and value
    return trie._verify_branch(branch, root, value)

def mk_account_proof_wrapper(db, blk, acct):
    """Generate a merkle proof wrapper for a given account in a given block

    The wrapper includes the
    1.block number,
    2.the state root of the block,
    3.rlp_encoded data of the account
    4.the merkle proof of the account
    5.indicator of whether the account is newly created
    """
    proof_wrapper = {}
    proof_wrapper['blk_number'] = blk.number
    proof_wrapper['state_root'] = '0x'+encode_hex(blk.header.state_root)
    rlpdata = trie._get(db, blk.header.state_root, trie.encode_bin(sha3(acct)))
    proof_wrapper['rlpdata'] = '0x'+encode_hex(rlpdata) if rlpdata else b''
    proof_wrapper['merkle_proof'] = get_merkle_proof(db, blk.header.state_root, acct) if rlpdata else []
    proof_wrapper['exist_yet'] = True if rlpdata else False
    return proof_wrapper
