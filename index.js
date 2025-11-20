document.addEventListener("DOMContentLoaded", function(event) {
    $input_priv = document.getElementById("input_priv");
    $input_xpriv = document.getElementById("input_xpriv");
    $input_pub = document.getElementById("input_pub");
    $input_msg = document.getElementById("input_msg");
    $output_sig = document.getElementById("output_sig");

    ui_clear();
});

function ui_init()
{
    $input_xpriv.value = "";
    $input_pub.value = "";
    $input_msg.value = "";
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
    if (!$input_msg.value || $input_msg.value.length === 0) {
        $input_msg.value = "317a5cd184cf5aa6ec86f8e0f510c4bb3cca8658";
    }
    //$output_script.value  = lamport_script(pubKey);
}

function ui_sign_message() {
    $output_sig.value = '';

    const privHex = ($input_priv && $input_priv.value || '').trim();
    const msgHex = ($input_msg && $input_msg.value || '').trim();

    assert(/^[0-9a-fA-F]+$/.test(privHex) && privHex.length == 64, "Private key needs to be 256 bit hexadecimal!");
    assert(/^[0-9a-fA-F]+$/.test(msgHex) && msgHex.length == 40, "Message must be 160 bit hexadecimal!");

    const privBytes = buffer.Buffer.from(privHex, 'hex');
    const msgBytes = buffer.Buffer.from(msgHex, 'hex'); // 20 bytes hash160 of some message

    const lam = new Lamport(privBytes, 20);
    const sigBytes = lam.sign(msgBytes); // returns Uint8Array
    
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

/*
function ui_sign_message() {
    const privEl = document.getElementById('input_priv');
    const msgEl = document.getElementById('input_msg');
    const outEl = document.getElementById('output_sig');
    outEl.value = '';

    const privHex = (privEl && privEl.value || '').trim();
    const msgHex = (msgEl && msgEl.value || '').trim();

    assert(/^[0-9a-fA-F]+$/.test(privHex) && privHex.length == 64, "Private key needs to be 256 bit hexadecimal!");
    assert(/^[0-9a-fA-F]+$/.test(msgHex) && msgHex.length == 40, "Message must be 160 bit hexadecimal!");

    try {
        const privBytes = buffer.Buffer.from(privHex, 'hex');
        const msgBytes = buffer.Buffer.from(msgHex, 'hex'); // 20 bytes hash160 of some message

        // Build Lamport instance with 20 trees (one per message byte)
        const lam = new Lamport(privBytes, 20);

        const parts = [];

        for (let t = 0; t < 20; t++) {
            const tree = lam.mTrees[t];
            const leafIndex = msgBytes[t]; // 0..255

            // collect sibling hashes from leaf up to root (depth1 .. depth8)
            let node = tree.leaves[leafIndex];
            const siblings = [];
            while (node.parent) {
                const parent = node.parent;
                const siblingNode = (parent.left === node) ? parent.right : parent.left;
                siblings.push(toUint8(siblingNode.value));
                node = parent;
            }

            if (siblings.length !== 8) {
                throw new Error('Unexpected merkle tree depth: expected 8, got ' + siblings.length);
            }

            // preimage from tree.preImages (now already 16 bytes)
            const pre16 = toUint8(tree.preImages[leafIndex]);

            // 1 byte control / branch value (leaf index)
            const control = new Uint8Array([leafIndex]);

            // order per spec: 8 sibling hashes (20 bytes each), 16 byte preimage, 1 byte control
            parts.push(...siblings, pre16, control);
        }

        const sig = concatUint8Arrays(parts);
        outEl.value = buffer.Buffer.from(sig).toString('hex');
    } catch (err) {
        throw new Error('Signing failed: ' + (err && err.message || err));
    }

    function toUint8(x) {
        if (!x) return new Uint8Array(0);
        if (x instanceof Uint8Array) return x;
        if (typeof Buffer !== 'undefined' && Buffer.isBuffer(x)) return new Uint8Array(x);
        if (x.buffer && x.byteLength !== undefined) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
        return new Uint8Array(Array.from(x));
    }
    function concatUint8Arrays(arrays) {
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
*/