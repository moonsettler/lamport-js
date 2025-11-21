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
            const leafHash = op_hash160(op_cat(iAsByteArray, preImage));

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

        //console.log("Lamport public key root: " + buffer.Buffer.from(root).toString('hex'));

        this.publicKey = op_hash256(root);
    }

    sign_160bit(envelope) {
        const envBytes = buffer.Buffer.from(envelope); // assume Uint8Array or Buffer
        const parts = [];

        //console.log(envBytes.toString('hex'));

        for (let t = 0; t < this.sigHashLen; t++) {
            const tree = this.mTrees[t];
            const leafIndex = envBytes[t]; // 0..255

            // collect sibling hashes from leaf up to root
            let node = tree.leaves[leafIndex];
            const siblings = [];
            while (node.parent) {
                const parent = node.parent;
                const siblingNode = (parent.left === node) ? parent.right : parent.left;
                siblings.push(this.toUint8(siblingNode.value));
                node = parent;
            }

            siblings.reverse(); // from root to leaf

            // verify tree depth (log2(nLeaves))
            const expectedDepth = Math.log2(tree.nLeaves);
            if (siblings.length !== expectedDepth) {
                throw new Error('Lamport.sign: unexpected merkle tree depth: expected ' + expectedDepth + ', got ' + siblings.length);
            }

            // preimage is prepared by LamportMerkleTree (already reduced to 16 bytes)
            const pre16 = this.toUint8(tree.preImages[leafIndex]);

            // control byte
            const control = new Uint8Array([leafIndex]);

            // push siblings (serialize in order the stack machine expects)
            // keep `siblings` in-memory as leaf->root for logic/inspection,
            // but store them reversed (root->leaf) so when the flattened
            // signature is unpacked into the VM stack it will be processed
            // in the correct order by the merkle_compress routine.
            parts.push(...siblings, pre16, control);
        }

        const sig = this.concatUint8Arrays(parts);

        return sig; // Uint8Array
    }

    /*  Debug functions, kept for development purposes (uncomment to use)
    // Print signature for a single tree in ASM format, with root hash as a comment
    debug_print_lamport_signature_tree(treeIndex, envelope) {
        const envBytes = buffer.Buffer.from(envelope);
        const tree = this.mTrees[treeIndex];
        const leafIndex = envBytes[treeIndex];

        // Print expected root hash for this tree as a comment
        console.log(`// root_hash: 0x${buffer.Buffer.from(tree.root.value).toString('hex')} //`);

        // collect sibling hashes from leaf up to root
        let node = tree.leaves[leafIndex];
        const siblings = [];
        while (node.parent) {
            const parent = node.parent;
            const siblingNode = (parent.left === node) ? parent.right : parent.left;
            siblings.push(this.toUint8(siblingNode.value));
            node = parent;
        }

        siblings.reverse(); // from root to leaf
        // Output siblings in leaf→root order (depth1..depth8)
        siblings.forEach((sib, i) => {
            console.log(`<0x${buffer.Buffer.from(sib).toString('hex')}> //`);
        });

        console.log(`// leaf_hash: <0x${buffer.Buffer.from(tree.leaves[leafIndex].value).toString('hex')}> //`);

        // leaf preimage (already 16 bytes)
        const pre16 = this.toUint8(tree.preImages[leafIndex]);
        console.log(`<0x${buffer.Buffer.from(pre16).toString('hex')}> //`);

        // control byte
        const control = new Uint8Array([leafIndex]);
        console.log(`<0x${buffer.Buffer.from(control).toString('hex')}> //`);
    }

    // Try different concatenation/bit-interpretation strategies to reproduce the tree root
    // This will test combinations and print which, if any, matches the stored tree root.
    debug_check_merkle_compression(treeIndex, envelope) {
        const envBytes = buffer.Buffer.from(envelope);
        const tree = this.mTrees[treeIndex];
        const leafIndex = envBytes[treeIndex];

        // collect siblings leaf->root
        let node = tree.leaves[leafIndex];
        const siblings = [];
        while (node.parent) {
            const parent = node.parent;
            const siblingNode = (parent.left === node) ? parent.right : parent.left;
            siblings.push(this.toUint8(siblingNode.value));
            node = parent;
        }

        const leafHash = this.toUint8(tree.leaves[leafIndex].value);
        const control = leafIndex & 0xff;
        const targetRoot = this.toUint8(tree.root.value);

        function hex(u8) { return buffer.Buffer.from(u8).toString('hex'); }

        const concatHash = (a, b) => op_hash160(op_cat(a, b));

        const orders = [ {name: 'leaf->root (as-collected)', arr: siblings.slice()}, {name: 'root->leaf (reversed)', arr: siblings.slice().reverse()} ];
        const rules = [
            {name: 'bit=1 => concat(current||sib), bit=0 => concat(sib||current)', fn: (bit, cur, sib) => (bit ? concatHash(cur, sib) : concatHash(sib, cur))},
            {name: 'bit=1 => concat(sib||current), bit=0 => concat(current||sib)', fn: (bit, cur, sib) => (bit ? concatHash(sib, cur) : concatHash(cur, sib))}
        ];

        console.log('debug_check_merkle_compression: leafIndex=', leafIndex, 'leafHash=', hex(leafHash), 'targetRoot=', hex(targetRoot));

        for (const order of orders) {
            for (const rule of rules) {
                let cur = leafHash;
                for (let i = 0; i < order.arr.length; i++) {
                    const sib = order.arr[i];
                    const bit = (control >> i) & 1;
                    cur = rule.fn(bit, cur, sib);
                }
                const match = hex(cur) === hex(targetRoot);
                console.log(`order=${order.name} rule=${rule.name} => result=${hex(cur)} match=${match}`);
            }
        }
    }
    */

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
