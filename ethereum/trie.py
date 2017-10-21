from ethereum.utils import sha3, encode_hex
from ethereum.utils import safe_ord as ord

# Binary utilities
# 0100000101010111010000110100100101001001 -> ASCII
def decode_bin(x):
    o = bytearray(len(x) // 8)
    for i in range(0, len(x), 8):
        v = 0
        for c in x[i:i+8]:
            v = v * 2 + c
        o[i//8] = v
    return bytes(o)

# ASCII -> 0100000101010111010000110100100101001001
def encode_bin(x):
    o = b''
    for c in x:
        c = ord(c)
        p = bytearray(8)
        for i in range(8):
            p[7-i] = c % 2
            c //= 2
        o += p
    return o

two_bits = [bytes([0,0]), bytes([0,1]),
            bytes([1,0]), bytes([1,1])]
prefix00 = bytes([0,0])
prefix100000 = bytes([1,0,0,0,0,0])

# Encodes a sequence of 0s and 1s into tightly packed bytes
def encode_bin_path(b):
    b2 = bytes((4 - len(b)) % 4) + b
    prefix = two_bits[len(b) % 4]
    if len(b2) % 8 == 4:
        return decode_bin(prefix00 + prefix + b2)
    else:
        return decode_bin(prefix100000 + prefix + b2)

# Decodes bytes into a sequence of 0s and 1s
def decode_bin_path(p):
    p = encode_bin(p)
    if p[0] == 1:
        p = p[4:]
    assert p[0:2] == prefix00
    L = two_bits.index(p[2:4])
    return p[4+((4 - L) % 4):]

def common_prefix_length(a, b):
    o = 0
    while o < len(a) and o < len(b) and a[o] == b[o]:
        o += 1
    return o


class EphemDB():
    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k, None)

    def put(self, k, v):
        self.kv[k] = v

    def delete(self, k):
        del self.kv[k]

KV_TYPE = 0
BRANCH_TYPE = 1
LEAF_TYPE = 2

b1 = bytes([1])
b0 = bytes([0])

# Input: a serialized node
def parse_node(node):
    if node[0] == BRANCH_TYPE:
        # Output: left child, right child, node type
        return node[1:33], node[33:], BRANCH_TYPE
    elif node[0] == KV_TYPE:
        # Output: keypath: child, node type
        return decode_bin_path(node[1:-32]), node[-32:], KV_TYPE
    elif node[0] == LEAF_TYPE:
        # Output: None, value, node type
        return None, node[1:], LEAF_TYPE
    else:
        raise Exception("Bad node")

# Serializes a key/value node
def encode_kv_node(keypath, node):
    assert keypath
    assert len(node) == 32
    o = bytes([KV_TYPE]) + encode_bin_path(keypath) + node
    return o

# Serializes a branch node (ie. a node with 2 children)
def encode_branch_node(left, right):
    assert len(left) == len(right) == 32
    return bytes([BRANCH_TYPE]) + left + right

# Serializes a leaf node
def encode_leaf_node(value):
    return bytes([LEAF_TYPE]) + value

# Saves a value into the database and returns its hash
def hash_and_save(db, node):
    h = sha3(node)
    db.put(h, node)
    return h

# Fetches the value with a given keypath from the given node
def _get(db, node, keypath):
    # Empty trie
    if not node:
        return None
    L, R, nodetype = parse_node(db.get(node))
    # Key-value node descend
    if nodetype == LEAF_TYPE:
        return R
    elif nodetype == KV_TYPE:
        if keypath[:len(L)] == L:
            return _get(db, R, keypath[len(L):])
        else:
            return None
    # Branch node descend
    elif nodetype == BRANCH_TYPE:
        if keypath[:1] == b0:
            return _get(db, L, keypath[1:])
        else:
            return _get(db, R, keypath[1:])

# Updates the value at the given keypath from the given node
def _update(db, node, keypath, val):
    # Empty trie
    if not node:
        if val:
            return hash_and_save(db, encode_kv_node(keypath, hash_and_save(db, encode_leaf_node(val))))
        else:
            return b''
    L, R, nodetype = parse_node(db.get(node))
    # Node is a leaf node
    if nodetype == LEAF_TYPE:
        return hash_and_save(db, encode_leaf_node(val)) if val else b''
    # node is a key-value node
    elif nodetype == KV_TYPE:
        # Keypath prefixes match
        if keypath[:len(L)] == L:
            # Recurse into child
            o = _update(db, R, keypath[len(L):], val)
            # If child is empty
            if not o:
                return b''
            #print(db.get(o))
            subL, subR, subnodetype = parse_node(db.get(o))
            # If the child is a key-value node, compress together the keypaths
            # into one node
            if subnodetype == KV_TYPE:
                return hash_and_save(db, encode_kv_node(L + subL, subR))
            else:
                return hash_and_save(db, encode_kv_node(L, o)) if o else b''
        # Keypath prefixes don't match. Here we will be converting a key-value node
        # of the form (k, CHILD) into a structure of one of the following forms:
        # i.   (k[:-1], (NEWCHILD, CHILD))
        # ii.  (k[:-1], ((k2, NEWCHILD), CHILD))
        # iii. (k1, ((k2, CHILD), NEWCHILD))
        # iv.  (k1, ((k2, CHILD), (k2', NEWCHILD))
        # v.   (CHILD, NEWCHILD)
        # vi.  ((k[1:], CHILD), (k', NEWCHILD))
        # vii. ((k[1:], CHILD), NEWCHILD)
        # viii (CHILD, (k[1:], NEWCHILD))
        else:
            cf = common_prefix_length(L, keypath[:len(L)])
            # valnode: the child node that has the new value we are adding
            # Case 1: keypath prefixes almost match, so we are in case (i), (ii), (v), (vi)
            if len(keypath) == cf + 1:
                valnode = val
            # Case 2: keypath prefixes mismatch in the middle, so we need to break
            # the keypath in half. We are in case (iii), (iv), (vii), (viii)
            else:
                valnode = hash_and_save(db, encode_kv_node(keypath[cf+1:], hash_and_save(db, encode_leaf_node(val))))
            # oldnode: the child node the has the old child value
            # Case 1: (i), (iii), (v), (vi)
            if len(L) == cf + 1:
                oldnode = R
            # (ii), (iv), (vi), (viii)
            else:
                oldnode = hash_and_save(db, encode_kv_node(L[cf+1:], R))
            # Create the new branch node (because the key paths diverge, there has to
            # be some "first bit" at which they diverge, so there must be a branch
            # node somewhere)
            if keypath[cf:cf+1] == b1:
                newsub = hash_and_save(db, encode_branch_node(oldnode, valnode))
            else:
                newsub = hash_and_save(db, encode_branch_node(valnode, oldnode))
            # Case 1: keypath prefixes match in the first bit, so we still need
            # a kv node at the top
            # (i) (ii) (iii) (iv)
            if cf:
                return hash_and_save(db, encode_kv_node(L[:cf], newsub))
            # Case 2: keypath prefixes diverge in the first bit, so we replace the
            # kv node with a branch node
            # (v) (vi) (vii) (viii)
            else:
                return newsub
    # node is a branch node
    elif nodetype == BRANCH_TYPE:
        newL, newR = L, R
        # Which child node to update? Depends on first bit in keypath
        if keypath[:1] == b0:
            newL = _update(db, L, keypath[1:], val)
        else:
            newR = _update(db, R, keypath[1:], val)
        # Compress branch node into kv node
        if not newL or not newR:
            subL, subR, subnodetype = parse_node(db.get(newL or newR))
            first_bit = b1 if newR else b0
            # Compress (k1, (k2, NODE)) -> (k1 + k2, NODE)
            if subnodetype == KV_TYPE:
                return hash_and_save(db, encode_kv_node(first_bit + subL, subR))
            # kv node pointing to a branch node
            elif subnodetype == BRANCH_TYPE:
                return hash_and_save(db, encode_kv_node(first_bit, newL or newR))
        else:
            return hash_and_save(db, encode_branch_node(newL, newR))
    raise Exception("How did I get here?")

# Prints a tree, and checks that all invariants check out
def print_and_check_invariants(db, node, prefix=b''):
    if node == b'' and prefix == b'':
        return {}
    L, R, nodetype = parse_node(db.get(node))
    if nodetype == LEAF_TYPE:
        # All keys must be 256 bits
        assert len(prefix) == 256
        return {prefix: R}
    elif nodetype == KV_TYPE:
        # (k1, (k2, node)) two nested key values nodes not allowed
        assert 0 < len(L) <= 256 - len(prefix)
        if len(L) + len(prefix) < 256:
            subL, subR, subnodetype = parse_node(db.get(R))
            assert subnodetype != KV_TYPE
            # Childre of a key node cannot be empty
            assert subR != sha3(b'')
        return print_and_check_invariants(db, R, prefix + L)
    else:
        # Children of a branch node cannot be empty
        assert L != sha3(b'') and R != sha3(b'')
        o = {}
        o.update(print_and_check_invariants(db, L, prefix + b0))
        o.update(print_and_check_invariants(db, R, prefix + b1))
        return o

# Pretty-print all nodes in a tree (for debugging purposes)
def print_nodes(db, node, prefix=b''):
    if node == b'':
        print('empty node')
        return
    L, R, nodetype = parse_node(db.get(node))
    if nodetype == LEAF_TYPE:
        print('value node', encode_hex(node[:4]), R)
    elif nodetype == KV_TYPE:
        print(('kv node:', encode_hex(node[:4]), ''.join(['1' if x == 1 else '0' for x in L]), encode_hex(R[:4])))
        print_nodes(db, R, prefix + L)
    else:
        print(('branch node:', encode_hex(node[:4]), encode_hex(L[:4]), encode_hex(R[:4])))
        print_nodes(db, L, prefix + b0)
        print_nodes(db, R, prefix + b1)

# Get a Merkle proof
def _get_branch(db, node, keypath):
    if not keypath:
        return [db.get(node)]
    L, R, nodetype = parse_node(db.get(node))
    if nodetype == KV_TYPE:
        path = encode_bin_path(L)
        if keypath[:len(L)] == L:
            return [b'\x01'+path] + _get_branch(db, R, keypath[len(L):])
        else:
            return [b'\x01'+path, db.get(R)]
    elif nodetype == BRANCH_TYPE:
        if keypath[:1] == b0:
            return [b'\x02'+R] + _get_branch(db, L, keypath[1:])
        else:
            return [b'\x03'+L] + _get_branch(db, R, keypath[1:])

# Verify a Merkle proof
def _verify_branch(branch, root, keypath, value):
    nodes = [branch[-1]]
    _keypath = b''
    for data in branch[-2::-1]:
        marker, node = data[0], data[1:]
        # it's a keypath
        if marker == 1:
            node = decode_bin_path(node)
            _keypath = node + _keypath
            nodes.insert(0, encode_kv_node(node, sha3(nodes[0])))
        # it's a right-side branch
        elif marker == 2:
            _keypath = b0 + _keypath
            nodes.insert(0, encode_branch_node(sha3(nodes[0]), node))
        # it's a left-side branch
        elif marker == 3:
            _keypath = b1 + _keypath
            nodes.insert(0, encode_branch_node(node, sha3(nodes[0])))
        else:
            raise Exception("Foo")
    if value:
        assert _keypath == keypath
    assert sha3(nodes[0]) == root
    db = EphemDB()
    db.kv = {sha3(node): node for node in nodes}
    assert _get(db, root, keypath) == value
    return True


BLANK_ROOT = b''
# Trie wrapper class
class Trie():
    def __init__(self, db, root=BLANK_ROOT):
        self.db = db
        self.root = root
        assert isinstance(self.root, bytes)

    @property
    def root_hash(self):
        return self.root

    @root_hash.setter
    def root_hash(self, value):
        self.root = value
        assert isinstance(self.root, bytes)

    def get(self, key):
        assert len(key) == 32
        return _get(self.db, self.root, encode_bin(key))

    def get_branch(self, key):
        assert len(key) == 32
        if(self.root == BLANK_ROOT):
            return []
        o = _get_branch(self.db, self.root, encode_bin(key))
        return o

    def update(self, key, value):
        assert len(key) == 32
        self.root = _update(self.db, self.root, encode_bin(key), value)

    def to_dict(self, hexify=False):
        o = print_and_check_invariants(self.db, self.root)
        encoder = lambda x: encode_hex(x) if hexify else x
        return {encoder(decode_bin(k)): v for k, v in o.items()}

    def print_nodes(self):
        print_nodes(self.db, self.root)        