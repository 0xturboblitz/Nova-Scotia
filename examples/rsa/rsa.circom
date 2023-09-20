pragma circom 2.0.3;

include "./fp.circom";

template RSA(n, k) {
    signal input step_in[2*k];  // base + modulus
    signal output step_out[2*k];    // Output after one RSA exponentiation step
    
    signal input intermediate_result[k];

    // Instantiate the necessary components
    component doubler = FpMul(n, k);
    
    // Set the modulus for the multiplication
    for (var j = 0; j < k; j++) {
        doubler.p[j] <== step_in[k+j];
    }
    
    // Assign inputs to the doubler
    for (var j = 0; j < k; j++) {
        doubler.a[j] <== step_in[j];
        doubler.b[j] <== step_in[j];
    }

    // check the intermediate result
    for (var j = 0; j < k; j++) {
        intermediate_result[j] === doubler.out[j];
        log(doubler.out[j]);
    }
    log("a");
    
    // Assign output
    for (var j = 0; j < k; j++) {
        step_out[j] <== doubler.out[j];
    }
    // copy modulus to end of output
    for (var j = k; j < 2*k; j++) {
        step_out[j] <== step_in[j];
    }
}

component main { public [step_in] } = RSA(64, 32);