function op_sha160(i1)
{
    assert_type(i1, nameof(i1), "Uint8Array");

    return bitcoinjs.crypto.hash160(i1);
}

function op_cat(i1, i2)
{
    assert_type(i2, nameof(i1), "Uint8Array");
    assert_type(i2, nameof(i2), "Uint8Array");

    var o = new Uint8Array(i1.length + i2.length);
    o.set(i1);
    o.set(i2, i1.length);
    return o;
}

function ui_init()
{
    document.getElementById("input_xpriv").value = "";
    document.getElementById("input_pub").value = "";
    document.getElementById("output_script").value = "";
}

function ui_clear()
{
    document.getElementById("input_priv").value = "";
    
    ui_init();
}

function ui_new_priv()
{
    ui_clear();

    const key = bitcoinjs.ECPair.makeRandom();

    document.getElementById("input_priv").value = key.privateKey.toString('hex');
}

function ui_generate()
{
    ui_init();

    const secret = document.getElementById("input_priv").value;
    
    assert(secret.length == 64, "Private key needs to be 256 bit hexadecimal!");

    const seed = buffer.Buffer.from( secret, "hex" );
    const root = bitcoinjs.bip32.fromSeed(seed);

    document.getElementById("input_xpriv").value = root.toBase58();

    const node = root.deriveHardened(69420);

    const child = node.deriveHardened(0).deriveHardened(0);

    const pk = child.privateKey;

    console.log(pk.toString('hex'));

    const h = op_sha160(pk);

    console.log(h.toString('hex'));

    document.getElementById("input_pub").value = h.toString('hex');
    document.getElementById("output_script").value  = lamport_script(h);
}
