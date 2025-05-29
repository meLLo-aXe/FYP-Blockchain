import hashlib

class merkleTree:
    def __init__(self, data_list):
        """
        Initialize the Merkle Tree with a list of data strings (e.g., votes).
        """
        if not data_list:
            raise ValueError("Data list cannot be empty")

        self.leaves = [self._hash(d) for d in data_list]
        self.tree = []
        self._build_tree()

    def _hash(self, data_str):
        """
        Return SHA-256 hex digest of a string.
        """
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

    def _build_tree(self):
        """
        Build the Merkle tree from leaves up to the root.
        """
        level = self.leaves
        self.tree.append(level)

        while len(level) > 1:
            if len(level) % 2 != 0:
                # Duplicate last hash if odd number of elements
                level.append(level[-1])

            next_level = []
            for i in range(0, len(level), 2):
                combined_hash = self._hash(level[i] + level[i + 1])
                next_level.append(combined_hash)
            self.tree.append(next_level)
            level = next_level

    def getMerkleRoot(self):
        """
        Return the Merkle root hash.
        """
        if self.tree:
            return self.tree[-1][0]
        return None
