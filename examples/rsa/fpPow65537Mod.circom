pragma circom 2.1.5;

include "./fp.circom";

// Computes base^65537 mod modulus
// Does not necessarily reduce fully mod modulus (the answer could be
// too big by a multiple of modulus)
template FpPow65537Mod(n, k) {
    // square and multiply method
    // base is the base message
    signal input base[k];
    // Exponent is hardcoded at 65537
    signal input modulus[k];
    signal output out[k];

    component doublers[16];
    component adder = FpMul(n, k);
    for (var i = 0; i < 16; i++) {
        doublers[i] = FpMul(n, k);
    }

    // p is always modulus, as it's the mod
    for (var j = 0; j < k; j++) {
        adder.p[j] <== modulus[j];
        for (var i = 0; i < 16; i++) {
            doublers[i].p[j] <== modulus[j];
        }
    }

    // for the first doubler, a and b are base. Why is b base? Because
    // we're computing base^2 mod modulus, and base^2 = base * base.
    for (var j = 0; j < k; j++) {
        doublers[0].a[j] <== base[j];
        doublers[0].b[j] <== base[j];
    }
    
    // for the rest of the doublers, a is the previous doubler's out, and
    // b is the previous doubler's out.
    for (var i = 0; i + 1 < 16; i++) {
        for (var j = 0; j < k; j++) {
            doublers[i + 1].a[j] <== doublers[i].out[j];
            doublers[i + 1].b[j] <== doublers[i].out[j];
        }
    }

    // add one mul by base to get to 65537
    for (var j = 0; j < k; j++) {
        adder.a[j] <== base[j];
        adder.b[j] <== doublers[15].out[j];
    }
    for (var j = 0; j < k; j++) {
        out[j] <== adder.out[j];
    }
}

template RSAVerify65537(n, k) {
    signal input signature[k];
    signal input modulus[k];
    signal input padded_message[k];
    // signal output out[k];

    // component padder = RSAPad(n, k);
    // for (var i = 0; i < k; i++) {
    //     padder.modulus[i] <== modulus[i];
    //     padder.base_message[i] <== base_message[i];
    // }

    // Check that the signature is in proper form and reduced mod modulus.
    component signatureRangeCheck[k];
    component bigLessThan = BigLessThan(n, k);
    for (var i = 0; i < k; i++) {
        signatureRangeCheck[i] = Num2Bits(n);
        signatureRangeCheck[i].in <== signature[i];
        bigLessThan.a[i] <== signature[i];
        bigLessThan.b[i] <== modulus[i];
    }
    bigLessThan.out === 1;

    component bigPow = FpPow65537Mod(n, k);
    for (var i = 0; i < k; i++) {
        bigPow.base[i] <== signature[i];
        bigPow.modulus[i] <== modulus[i];
    }
    // By construction of the padding, the padded message is necessarily
    // smaller than the modulus. Thus, we don't have to check that bigPow is fully reduced.
    for (var i = 0; i < k; i++) {
        bigPow.out[i] === padded_message[i];
    }
}

component main{public [modulus]} = RSAVerify65537(64, 32);