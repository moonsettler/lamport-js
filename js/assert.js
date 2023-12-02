const nameof = exp => Object.keys(exp).pop();

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || " Assertion failed");
    }
}

function assert_type(obj, vname, tname) {
    if(typeof obj == "object")
    {
        assert(Object.prototype.toString.call(obj) == `[object ${tname}]`, `${vname}: ${tname}}`);
    }
    else
    {
        assert(typeof obj == tname, `${vname}: ${tname}}`);
    }
}
