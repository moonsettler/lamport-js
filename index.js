document.addEventListener("DOMContentLoaded", function(event) {
    $input_priv = document.getElementById("input_priv");
    $input_xpriv = document.getElementById("input_xpriv");
    $input_pub = document.getElementById("input_pub");
    $input_msg = document.getElementById("input_msg");
    $output_msg_hash = document.getElementById("output_msg_hash");
    $output_sig = document.getElementById("output_sig");

    ui_clear();
});

function ui_init()
{
    $input_xpriv.value = "";
    $input_pub.value = "";
    $input_msg.value = "";
    $output_msg_hash.value = "";
    $output_sig.value = "";
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
    
    assert(/^[0-9a-fA-F]+$/.test(secret) && secret.length == 64, "Private key needs to be 256 bit hexadecimal!");
    
    const seed = buffer.Buffer.from(secret, "hex");

    const lamport = new Lamport(seed, 20);

    $input_xpriv.value = lamport.xpriv;

    const pubKey = lamport.publicKey;

    $input_pub.value = pubKey.toString('hex');
}

function ui_sign_message() {
    $output_msg_hash.value = '';
    $output_sig.value = '';

    const privHex = ($input_priv && $input_priv.value || '').trim();
    const msgHex = ($input_msg && $input_msg.value || '').trim();

    assert(/^[0-9a-fA-F]+$/.test(privHex) && privHex.length == 64, "Private key needs to be 256 bit hexadecimal!");
    assert(/^[0-9a-fA-F]+$/.test(msgHex),  "Message must be hexadecimal!");

    const privBytes = buffer.Buffer.from(privHex, 'hex');
    const msgBytes = buffer.Buffer.from(msgHex, 'hex'); // some message

    const envelopeBytes = op_hash160(msgBytes); // hash160 of the message

    $output_msg_hash.value = envelopeBytes.toString('hex');

    const lam = new Lamport(privBytes, 20);
    const sigBytes = lam.sign_160bit(envelopeBytes); // returns Uint8Array

    //lam.debug_print_lamport_signature_tree(19, envelopeBytes);
    //lam.debug_check_merkle_compression(19, envelopeBytes);
    
    $output_sig.value = buffer.Buffer.from(sigBytes).toString('hex');
}

function ui_copy_sig() {
    const el = document.getElementById('output_sig') || $output_sig;
    const text = (el && el.value) || '';
    if (!text) { alert('No signature to copy'); return; }

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => fallbackCopy());
    } else {
        fallbackCopy();
    }

    function fallbackCopy() {
        try {
            // ensure element is focusable/selectable
            if (el.select) {
                el.select();
                document.execCommand('copy');
                if (window.getSelection) window.getSelection().removeAllRanges();
            } else {
                // final fallback: prompt so user can manually copy
                window.prompt('Copy signature (Ctrl+C, Enter):', text);
            }
        } catch (e) {
            window.prompt('Copy signature (Ctrl+C, Enter):', text);
        }
    }
}
