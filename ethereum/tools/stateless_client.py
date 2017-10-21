import rlp

from ethereum.utils import sha3, encode_hex
from ethereum import trie


def get_merkle_proof(db, root, value):
    """Get the merkle proof of a given value in trie
    
    value must exist in trie or exception will be thrown

    returns a list of nodes starting from root to leaf node
    """
    assert db and root and value
    key = sha3(value)
    return trie._get_branch(db, root, trie.encode_bin(key)) 

def verify_merkle_proof(branch, root, key, value):
    """Verify if a given value exist in trie

    returns true or false
    """
    assert branch and root and key
    return trie._verify_branch(branch, root, trie.encode_bin(key), value)

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
    proof_wrapper['rlpdata'] = rlpdata
    proof_wrapper['merkle_proof'] = get_merkle_proof(db, blk_header.state_root, acct)
    return proof_wrapper

def mk_pending_tx_bundle(db, tx, latest_blk_header):
    """Generate transaction bundle for pending transaction which

    includes transaction itself and merkle proof for accounts in

    read/write list of the transaction
    """
    from ethereum.transactions import Transaction
    tx_bundle = {"tx_data": rlp.encode(tx, Transaction)}
    read_list_proof = []
    for acct in tx.read_list:
        o = mk_account_proof_wrapper(db, latest_blk_header, acct)
        read_list_proof.append({acct: o})
    tx_bundle["read_list_proof"] = read_list_proof
    write_list_proof = []
    for acct in tx.write_list:
        o = mk_account_proof_wrapper(db, latest_blk_header, acct)
        write_list_proof.append({acct: o})
    tx_bundle["write_list_proof"] = write_list_proof

def mk_confirmed_tx_bundle(db, tx, prev_blk_header, latest_blk_header):
    """Generate transaction bundle for confirmed transaction which

    includes two part:
    
    the first part includes transaction itself, merkle proof for accounts in

    read/write list of the transaction and merkle proof for coinbase account

    the second part, `updated_acct_proof`, provides updated data and merkle proof
    
    for coinbase account and accounts in read/write list so that stateless client

    can just update the state trie after verifying the proofs
    """
    from ethereum.transactions import Transaction
    tx_bundle = {"tx_data": rlp.encode(tx, Transaction)}
    read_list_proof = []
    for acct in tx.read_list + (latest_blk_header.coinbase,):
        o = mk_account_proof_wrapper(db, prev_blk_header, acct)
        read_list_proof.append({acct: o})
    tx_bundle["read_list_proof"] = read_list_proof
    write_list_proof = []
    for acct in tx.write_list + (latest_blk_header.coinbase,):
        o = mk_account_proof_wrapper(db, prev_blk_header, acct)
        write_list_proof.append({acct: o})
    tx_bundle["write_list_proof"] = write_list_proof
    updated_acct_list = []
    for acct in tx.read_write_union_list | set(latest_blk_header.coinbase):
        o = mk_account_proof_wrapper(db, latest_blk_header, acct)
        updated_acct_list.append({acct: o})
    tx_bundle["updated_acct_proof"] = updated_acct_list
    return tx_bundle

def verify_tx_bundle(env, state_root, coinbase, tx_bundle):
    # Initialize a ephemeral state
    from ethereum.state import State
    from ethereum.db import EphemDB, RefcountDB
    from ethereum.messages import apply_transaction
    ephem_state = State(state_root, env)
    ephem_state.trie.db = RefcountDB(EphemDB())
    ephem_state.trie.db.put(sha3(b''), b'')
    ephem_state.block_coinbase = coinbase

    # Verify merkle proofs and store the nodes in state trie
    for acct_proof_wrapper in tx_bundle["read_list_proof"]:
        for acct, wrapper in acct_proof_wrapper.items():
            assert state_root == wrapper["state_root"]
            assert verify_merkle_proof(wrapper["merkle_proof"], wrapper["state_root"], sha3(acct), wrapper["rlpdata"])
            # Store the new account data after verifying the proof
            store_merkle_branch_nodes(ephem_state.trie.db, wrapper["merkle_proof"])
    # Do the same to write list proof
    for acct_proof_wrapper in tx_bundle["write_list_proof"]:
        for acct, wrapper in acct_proof_wrapper.items():
            assert state_root == wrapper["state_root"]
            assert verify_merkle_proof(wrapper["merkle_proof"], wrapper["state_root"], sha3(acct), wrapper["rlpdata"])
            # Store the new account data after verifying the proof
            store_merkle_branch_nodes(ephem_state.trie.db, wrapper["merkle_proof"])

    # Apply and verify the transaction
    from ethereum.transactions import Transaction
    success, _ = apply_transaction(ephem_state, rlp.decode(tx_bundle["tx_data"], Transaction))
    return success