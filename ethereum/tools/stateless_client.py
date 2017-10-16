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

def store_merkle_branch_nodes(db, branch):
    """Store the nodes of the merkle proof branch in db
    """
    nodes = [branch[-1]]
    trie.hash_and_save(db, nodes[0])
    for data in branch[-2::-1]:
        marker, node = data[0], data[1:]
        if marker == 1:
            node = trie.decode_bin_path(node)
            nodes.insert(0, trie.encode_kv_node(node, sha3(nodes[0])))
        elif marker == 2:
            nodes.insert(0, trie.encode_branch_node(sha3(nodes[0]), node))
        elif marker == 3:
            nodes.insert(0, trie.encode_branch_node(node, sha3(nodes[0])))
        else:
            raise Exception("Corrupted branch")
        trie.hash_and_save(db, nodes[0])

def mk_account_proof_wrapper(db, blk_header, acct):
    """Generate a merkle proof wrapper for a given account in a given block

    The wrapper includes the
    1.block number,
    2.the state root of the block,
    3.rlp_encoded data of the account
    4.the merkle proof of the account
    5.indicator of whether the account is newly created
    """
    proof_wrapper = {}
    proof_wrapper['blk_number'] = blk_header.number
    # proof_wrapper['state_root'] = '0x'+encode_hex(blk_header.state_root)
    proof_wrapper['state_root'] = blk_header.state_root
    rlpdata = trie._get(db, blk_header.state_root, trie.encode_bin(sha3(acct)))
    # proof_wrapper['rlpdata'] = '0x'+encode_hex(rlpdata) if rlpdata else b''
    proof_wrapper['rlpdata'] = rlpdata if rlpdata else b''
    proof_wrapper['merkle_proof'] = get_merkle_proof(db, blk_header.state_root, acct) if rlpdata else []
    proof_wrapper['exist_yet'] = True if rlpdata else False
    return proof_wrapper

def mk_tx_bundle(db, tx, prev_blk_header, cur_blk_header):
    tx_bundle = {"tx_data": tx.to_dict()}
    read_list_proof = []
    for acct in tx.read_list:
        o = mk_account_proof_wrapper(db, prev_blk_header, acct)
        read_list_proof.append({acct: o})
    tx_bundle["read_list_proof"] = read_list_proof
    write_list_proof = []
    for acct in tx.write_list:
        o = mk_account_proof_wrapper(db, prev_blk_header, acct)
        write_list_proof.append({acct: o})
    tx_bundle["write_list_proof"] = write_list_proof
    updated_acct_list = []
    for acct in tx.read_write_union_list:
        o = mk_account_proof_wrapper(db, cur_blk_header, acct)
        updated_acct_list.append({acct: o})
    tx_bundle["updated_acct_proof"] = updated_acct_list
    return tx_bundle