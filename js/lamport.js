class LamportMerkleTree {
    constructor(node, nLeaves) {
        this.nLeaves = nLeaves;
        this.preImages = new Array();
        this.leaves = new Array();

        for(var i = 0; i < nLeaves; i++)
        {
            const child = node.deriveHardened(i);

            const pk = child.privateKey;

            const pi = op_sha160(pk);

            this.preImages.push(pi);

            const iba = new Uint8Array(1);
            iba[0] = i;

            const h = op_sha160(op_cat(pi, iba));

            this.leaves.push(h);

            console.log(`hash160(${pi.toString('hex')}+${i.toString(16)}): ${h.toString('hex')}`);
        }
    }
}

class Lamport {
    constructor(privateKey, sigHashLen)
    {
        this.sigHashLen = sigHashLen;
        this.mTrees = new Array();
        this.privateKey = privateKey;

        const root = bitcoinjs.bip32.fromSeed(privateKey);

        this.xpriv = root.toBase58();

        const node = root.deriveHardened(69420);

        for(var i = 0; i < sigHashLen; i++)
        {
            console.log(`${i}:`);

            const child = node.deriveHardened(i);

            const merkleTree = new LamportMerkleTree(child, 256);

            this.mTrees.push(merkleTree);
        }

        const pk = root.privateKey;

        console.log(pk.toString('hex'));

        const h = op_sha160(pk);

        this.publicKey = h;
    }
}