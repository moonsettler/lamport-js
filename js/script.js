function op_hash160(i1)
{
    //assert_type(i1, "Uint8Array");

    return bitcoinjs.crypto.hash160(i1);
}

function op_cat(i1, i2)
{
    //assert_type(i1, "Uint8Array");
    //assert_type(i2, "Uint8Array");

    var o = new Uint8Array(i1.length + i2.length);
    o.set(i1);
    o.set(i2, i1.length);
    return o;
}

function snippet_byte_start(j)
{
    return `// *** ${j} byte of <sighash>
OP_DUP
OP_TOALTSTACK  // <byte-value>
OP_CAT
OP_HASH160

`;
}

function snippet_merkle_verify(j, i)
{
    return `// ${i} of ${j} merkle verify step
OP_SWAP
OP_IF
OP_SWAP
OP_ENDIF
OP_CAT
OP_HASH160`
}

function snippet_update_alt_stack()
{
    return `
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_CAT
OP_TOALTSTACK
OP_CAT
OP_HASH160
OP_TOALTSTACK`
}

function lamport_script(pubkey)
{
    var script = `// witness script
`;
    for(j = 0; j < 20; j++)
    {
        script += snippet_byte_start(j+1);

        for(i = 0; i < 8; i++)
        {
            script += snippet_merkle_verify(j+1, i+1);
            script += "\r\n";
            script += "\r\n";
        }

        if(j == 0)
        {
            script += `// *** ${j+1} push state to alt-stack
OP_TOALTSTACK // <pubkey-build>

`;
        }
        else{
            script += `// *** ${j+1} update state on alt-stack
OP_FROMALTSTACK // <byte-value>

// stack: ... <merkle-root> <byte-value> | alt-stack: <sighash-build> <pubkey-build>
${snippet_update_alt_stack()}

`;
        }
    }

    script += `// *** finished building the sighash and pubkey
OP_FROMALTSTACK // <pubkey>

<0x${pubkey.toString('hex')}>
OP_EQUALVERIFY

OP_FROMALTSTACK // <sighash>`;

    return script;
}
