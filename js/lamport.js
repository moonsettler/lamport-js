class LamportMerkleNode {
    constructor(left, right, value) {
        this.parent = undefined;
        this.left = left;
        this.right = right;
        this.value = value;
    }
    static newNode(left, right) {
        return new LamportMerkleNode(left, right, op_hash160(op_cat(left.value, right.value)));
    }
    static newLeaf(value) {
        return new LamportMerkleNode(undefined, undefined, value);
    }
}

class LamportMerkleTree {
    constructor(node, nLeaves) {
        this.nLeaves = nLeaves;
        this.preImages = new Array();
        this.leaves = new Array();

        for(var i = 0; i < nLeaves; i++)
        {
            const child = node.deriveHardened(i);

            const priv = child.privateKey;

            const preImage = op_hash160(priv);

            this.preImages.push(preImage);

            const iAsByteArray = new Uint8Array(1);
            iAsByteArray[0] = i;

            const leafHash = op_hash160(op_cat(preImage, iAsByteArray));

            const leafNode = LamportMerkleNode.newLeaf(leafHash);
            
            this.leaves.push(leafNode);
        }

        this.root = LamportMerkleTree.merklize(this.leaves)[0];
    }

    static merklize(arrayNodes)
    {
        if(arrayNodes.length == 1)
        {
            return arrayNodes;
        }

        const currentState = new Array();
        const n = arrayNodes.length;

        for(var i = 0; i < n; i += 2)
        {
            const node = LamportMerkleNode.newNode(arrayNodes[i], arrayNodes[i+1]);
            arrayNodes[i].parent = node;
            arrayNodes[i+1].parent = node;

            currentState.push(node);
        }

        return(LamportMerkleTree.merklize(currentState));
    }
}

class Lamport {
    constructor(privateKey, sigHashLen)
    {
        this.sigHashLen = sigHashLen;
        this.mTrees = new Array();
        this.privateKey = privateKey;

        const seed = bitcoinjs.bip32.fromSeed(privateKey);

        this.xpriv = seed.toBase58();

        const node = seed.deriveHardened(69420);

        for(var i = 0; i < sigHashLen; i++)
        {
            const child = node.deriveHardened(i);

            const merkleTree = new LamportMerkleTree(child, 256);

            this.mTrees.push(merkleTree);
        }

        var root = this.mTrees[0].root.value;

        for(var i = 1; i < sigHashLen; i++)
        {
            root = op_hash160(op_cat(root, this.mTrees[i].root.value));
        }

        this.publicKey = root;
    }
}