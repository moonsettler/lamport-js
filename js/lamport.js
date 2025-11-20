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

            // full 20-byte hash160 of private child
            const fullPreImage = op_hash160(priv);

            // reduce to 16 bytes here (affects public key/root generation)
            const preImage = fullPreImage.slice(0, 16);

            this.preImages.push(preImage);

            const iAsByteArray = new Uint8Array(1);
            iAsByteArray[0] = i;

            // use the 16-byte preimage consistently for leaf hash
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
            root = op_cat(root, this.mTrees[i].root.value);
        }

        this.publicKey = op_hash256(root);
    }

    sign(message) {
        // message: hex string, Buffer, or Uint8Array
        /*
        const msgBytes = (function(m) {
            if (!m) return new Uint8Array(0);
            if (typeof m === 'string') {
                // hex string
                const len = m.length / 2;
                const out = new Uint8Array(len);
                for (let i = 0; i < len; i++) out[i] = parseInt(m.substr(i*2, 2), 16);
                return out;
            }
            if (typeof Buffer !== 'undefined' && Buffer.isBuffer(m)) return new Uint8Array(m);
            if (m instanceof Uint8Array) return m;
            if (m.buffer && m.byteLength !== undefined) return new Uint8Array(m.buffer, m.byteOffset, m.byteLength);
            return new Uint8Array(Array.from(m));
        })(message);

        if (msgBytes.length !== this.sigHashLen) {
            throw new Error('Lamport.sign: message length mismatch, expected ' + this.sigHashLen + ' bytes');
        }
         */

        const msgBytes = buffer.Buffer.from(message); // assume Uint8Array or Buffer
        const parts = [];
        for (let t = 0; t < this.sigHashLen; t++) {
            const tree = this.mTrees[t];
            const leafIndex = msgBytes[t]; // 0..255

            // collect sibling hashes from leaf up to root
            let node = tree.leaves[leafIndex];
            const siblings = [];
            while (node.parent) {
                const parent = node.parent;
                const siblingNode = (parent.left === node) ? parent.right : parent.left;
                siblings.push(this.toUint8(siblingNode.value));
                node = parent;
            }

            // verify tree depth (log2(nLeaves))
            const expectedDepth = Math.log2(tree.nLeaves);
            if (siblings.length !== expectedDepth) {
                throw new Error('Lamport.sign: unexpected merkle tree depth: expected ' + expectedDepth + ', got ' + siblings.length);
            }

            // preimage is prepared by LamportMerkleTree (already reduced to 16 bytes)
            const pre16 = this.toUint8(tree.preImages[leafIndex]);

            // control byte
            const control = new Uint8Array([leafIndex]);

            // push siblings (order: from leaf upward), then preimage, then control
            parts.push(...siblings, pre16, control);
        }

        const sig = this.concatUint8Arrays(parts);

        return sig; // Uint8Array
    }

    // helper functions (kept in file-scope so sign can use them)
    toUint8(x) {
        if (!x) return new Uint8Array(0);
        if (x instanceof Uint8Array) return x;
        if (typeof Buffer !== 'undefined' && Buffer.isBuffer(x)) return new Uint8Array(x);
        if (x.buffer && x.byteLength !== undefined) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
        return new Uint8Array(Array.from(x));
    }
    concatUint8Arrays(arrays) {
        let total = 0;
        for (const a of arrays) total += a.length;
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            out.set(a, offset);
            offset += a.length;
        }
        return out;
    }
}
