use super::rsa_public_der;

#[test]
fn rsa_dnskey_components_are_limited_to_4096_bits() {
    let mut valid = vec![1, 3];
    valid.extend(vec![1; 512]);
    assert!(rsa_public_der(&valid).is_ok());

    let mut oversized_modulus = vec![1, 3];
    oversized_modulus.extend(vec![1; 513]);
    assert!(rsa_public_der(&oversized_modulus).is_err());

    let mut oversized_exponent = vec![0, 2, 1];
    oversized_exponent.extend(vec![1; 513]);
    oversized_exponent.push(3);
    assert!(rsa_public_der(&oversized_exponent).is_err());
}

// RFC 3110 §2: Reject noncanonical exponent lengths and leading zero octets.
#[test]
fn rsa_dnskey_rejects_noncanonical_exponent_lengths_and_leading_zeroes() {
    let mut extended_short_exponent = vec![0, 0, 255];
    extended_short_exponent.extend(vec![1; 255]);
    extended_short_exponent.push(3);
    assert!(rsa_public_der(&extended_short_exponent).is_err());

    assert!(rsa_public_der(&[2, 0, 3, 5]).is_err());
    assert!(rsa_public_der(&[1, 3, 0, 5]).is_err());

    let mut extended_long_exponent = vec![0, 1, 0];
    extended_long_exponent.extend(vec![1; 256]);
    extended_long_exponent.push(3);
    assert!(rsa_public_der(&extended_long_exponent).is_ok());
}
