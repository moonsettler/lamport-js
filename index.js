document.addEventListener("DOMContentLoaded", function(event) {
    $input_priv = document.getElementById("input_priv");
    $input_xpriv = document.getElementById("input_xpriv");
    $input_pub = document.getElementById("input_pub");
    $output_script = document.getElementById("output_script");

    ui_clear();
});

function ui_init()
{
    $input_xpriv.value = "";
    $input_pub.value = "";
    $output_script.value = "";
}

function ui_clear()
{
    $input_priv.value = "";
    
    ui_init();
}

function ui_new_priv()
{
    ui_clear();

    const key = bitcoinjs.ECPair.makeRandom();

    $input_priv.value = key.privateKey.toString('hex');
}

function ui_generate()
{
    ui_init();

    const secret = document.getElementById("input_priv").value;
    
    assert(secret.length == 64, "Private key needs to be 256 bit hexadecimal!");
    
    const seed = buffer.Buffer.from(secret, "hex");

    const lamport = new Lamport(seed, 20);

    $input_xpriv.value = lamport.xpriv;

    const pubKey = lamport.publicKey;

    $input_pub.value = pubKey.toString('hex');
    $output_script.value  = lamport_script(pubKey);
}
