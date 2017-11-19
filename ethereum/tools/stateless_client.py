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
    """Store the nodes of the merkle branch into db
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

def mk_tx_bundle(state, tx, state_root):
    """Generate transaction bundle for transaction which includes:
    
    1. tx data
    2. list of merkle proof of each account in read/write list
    3. list of {sha3(code): code} pair
    """
    from ethereum.state import Account
    from ethereum.transactions import Transaction
    tx_bundle = {"tx_rlpdata": rlp.encode(tx, Transaction)}
    code_set = set()
    account_proof_list = []
    for acct in tx.read_write_union_list:
        acct_proof = get_merkle_proof(state.trie.db, state_root, acct)
        acct_rlp = acct_proof[-1]
        code = rlp.decode(acct_rlp, Account, env=state.env, address=acct).code
        if code:
            code_set.add(code)
        account_proof_list.append({acct: acct_proof})
    tx_bundle["account_proof_list"] = account_proof_list
    code_list = []
    for code in code_set:
        code_list.append({sha3(code): code})
    tx_bundle["code_list"] = code_list
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

    # Verify merkle proofs
    # for proof_wrapper in tx_bundle["account_proof_list"]:
    #     for acct, proof in proof_wrapper.items():
    #         assert verify_merkle_proof(proof, state_root, sha3(acct), )
    
    # Store the trie nodes and the codes into database
    for proof_wrapper in tx_bundle["account_proof_list"]:
        for _, proof in proof_wrapper.items():
            store_merkle_branch_nodes(ephem_state.trie.db, proof)
    for code_pair in tx_bundle["code_list"]:
        for code_hash, code in code_pair.items():
            ephem_state.env.db.put(code_hash, code)

    # Apply and verify the transaction
    from ethereum.transactions import Transaction
    success, _ = apply_transaction(ephem_state, rlp.decode(tx_bundle["tx_rlpdata"], Transaction))
    ephem_state.commit()
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
                mk_tx_bundle(state, tx,
                    state.trie.root_hash))
            success, _ = apply_transaction(state, tx)
            assert success
        # Commit txs to get the intermediate state root between each group
        state.commit()
        # Mark the block number as -1 if proof is calculated base on intermediate state root
        if i == 0:
            block_number = -1
    target_block.tx_bundle_list = tx_bundle_list
