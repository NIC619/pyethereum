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

def mk_account_proof_wrapper(state_trie_db, state_env, state_root, acct):
    """Generate a merkle proof wrapper for a given account in a given block

    The wrapper includes the
    1.block number,
    2.the state root of the block,
    3.rlp_encoded data of the account
    4.the merkle proof of the account
    5.indicator of whether the account is newly created
    """
    proof_wrapper = {}
    proof_wrapper["acct_rlpdata"] = trie._get(
        state_trie_db, state_root, trie.encode_bin(sha3(acct)))
    proof_wrapper["merkle_proof"] = get_merkle_proof(state_trie_db, state_root, acct)
    from ethereum.state import Account
    if proof_wrapper["acct_rlpdata"]:
        proof_wrapper["code"] = rlp.decode(
            proof_wrapper["acct_rlpdata"], Account, env=state_env, address=acct
        ).code
    else:
        proof_wrapper["code"] = b''
    return proof_wrapper

def mk_pending_tx_bundle(state, tx, latest_blk_number, latest_blk_state_root):
    """Generate transaction bundle for pending transaction which

    includes transaction itself and merkle proof for accounts in

    read/write list of the transaction
    """
    from ethereum.transactions import Transaction
    tx_bundle = {"tx_rlpdata": rlp.encode(tx, Transaction)}
    tx_bundle["block_number"] = latest_blk_number
    tx_bundle["state_root"] = latest_blk_state_root
    read_list_proof = []
    for acct in tx.read_list:
        o = mk_account_proof_wrapper(state.trie.db, state.env, latest_blk_state_root, acct)
        read_list_proof.append({acct: o})
    tx_bundle["read_list_proof"] = read_list_proof
    write_list_proof = []
    for acct in tx.write_list:
        o = mk_account_proof_wrapper(state.trie.db, state.env, latest_blk_state_root, acct)
        write_list_proof.append({acct: o})
    tx_bundle["write_list_proof"] = write_list_proof
    return tx_bundle

def mk_confirmed_tx_bundle(state, tx, prev_blk_number, prev_blk_state_root, latest_blk_state_root, coinbase):
    """Generate transaction bundle for confirmed transaction which includes two part:
    
    1. the first part includes transaction itself, merkle proof for accounts in

    read/write list of the transaction and merkle proof for coinbase account

    2. the second part, `updated_acct_proof`, provides updated data and merkle proof
    
    for coinbase account and accounts in read/write list so that stateless client

    can just update the state trie with this after verifying the proofs
    """
    from ethereum.transactions import Transaction
    tx_bundle = {"tx_rlpdata": rlp.encode(tx, Transaction)}
    tx_bundle["block_number"] = prev_blk_number
    tx_bundle["state_root"] = prev_blk_state_root
    read_list_proof = []
    for acct in tx.read_list + (coinbase,):
        o = mk_account_proof_wrapper(state.trie.db, state.env, prev_blk_state_root, acct)
        read_list_proof.append({acct: o})
    tx_bundle["read_list_proof"] = read_list_proof
    write_list_proof = []
    for acct in tx.write_list + (coinbase,):
        o = mk_account_proof_wrapper(state.trie.db, state.env, prev_blk_state_root, acct)
        write_list_proof.append({acct: o})
    tx_bundle["write_list_proof"] = write_list_proof
    updated_acct_list = []
    for acct in tx.read_write_union_list | set(coinbase):
        o = mk_account_proof_wrapper(state.trie.db, state.env, latest_blk_state_root, acct)
        updated_acct_list.append({acct: o})
    tx_bundle["updated_acct_proof"] = updated_acct_list
    return tx_bundle

def verify_tx_bundle(env, state_root, coinbase, tx_bundle):
    # Initialize a ephemeral state
    from ethereum.config import Env
    from ethereum.state import State
    from ethereum.db import EphemDB, RefcountDB
    from ethereum.messages import apply_transaction
    ephem_state = State(state_root, Env(EphemDB(), env.config, env.global_config))
    ephem_state.trie.db.put(sha3(b''), b'')
    ephem_state.block_coinbase = coinbase

    # Verify merkle proofs and store the nodes in state trie
    assert state_root == tx_bundle["state_root"]
    for acct_proof_wrapper in tx_bundle["read_list_proof"]:
        for acct, wrapper in acct_proof_wrapper.items():
            assert verify_merkle_proof(wrapper["merkle_proof"],
                tx_bundle["state_root"], sha3(acct), wrapper["acct_rlpdata"])
            # Store the account data after verifying the proof
            if wrapper["code"]:
                ephem_state.env.db.put(sha3(wrapper["code"]), wrapper["code"])
            store_merkle_branch_nodes(ephem_state.trie.db, wrapper["merkle_proof"])
    # Do the same to write list proof
    for acct_proof_wrapper in tx_bundle["write_list_proof"]:
        for acct, wrapper in acct_proof_wrapper.items():
            assert verify_merkle_proof(wrapper["merkle_proof"],
                tx_bundle["state_root"], sha3(acct), wrapper["acct_rlpdata"])
            # Store the account data after verifying the proof
            if wrapper["code"]:
                ephem_state.env.db.put(sha3(wrapper["code"]), wrapper["code"])
            store_merkle_branch_nodes(ephem_state.trie.db, wrapper["merkle_proof"])

    # Apply and verify the transaction
    from ethereum.transactions import Transaction
    success, _ = apply_transaction(ephem_state, rlp.decode(tx_bundle["tx_rlpdata"], Transaction))
    return success

def group_txs(txs):
    groups = []
    current_set = set()
    current_group = []
    for tx in txs:
        # If accounts in tx's read/write list overlap 
        # account's in current tx group's read/write list,
        # end the current group and start a new one
        if not (tx.read_write_union_list.isdisjoint(current_set)):
            groups.append(current_group)
            current_set = tx.read_write_union_list
            current_group = [tx]
        else:
            current_group.append(tx)
            current_set |= tx.read_write_union_list
    groups.append(current_group)
    return groups

def attach_tx_bundles_to_txs_in_block(state, prev_block_header, target_block):
    from ethereum.messages import apply_transaction
    from ethereum.transactions import Transaction
    block_number = prev_block_header.number

    tx_bundle_list = []
    grouped_txs = group_txs(target_block.transactions)
    for i, group in enumerate(grouped_txs):
        for tx in group:
            tx_bundle_list.append(
                mk_confirmed_tx_bundle(state, tx, block_number,
                    state.trie.root_hash, target_block.header.state_root, target_block.header.coinbase))
            success, _ = apply_transaction(state, tx)
            assert success
        # Commit txs to get the intermediate state root between each group
        state.commit()
        # Mark the block number as -1 if proof is calculated base on intermediate state root
        if i == 0:
            block_number = -1
    target_block.tx_bundle_list = tx_bundle_list
