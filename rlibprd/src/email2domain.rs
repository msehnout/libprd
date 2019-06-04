use data_encoding::HEXLOWER;
use openssl::sha;

pub fn email2domain(email_address: &str) -> Result<String, &'static str> {
    let split: Vec<_> = email_address.split('@').collect();
    if split.len() == 2 {
        let local = split[0];
        let domain = split[1];
        let mut hasher = sha::Sha256::new();
        hasher.update(local.as_bytes());
        let digest = hasher.finish();
        let digest_str = HEXLOWER.encode(&digest[0..28]);
        Ok(format!("{}._openpgpkey.{}", &digest_str, domain))
    } else {
        Err("The email did not contain exactly one @ sign.")
    }
}

#[test]
fn test_fedora_domain() {
    let input = "fedora-29@fedoraproject.org";
    let output = "557d8ff0f0f4c6c9fc7140670cc85400dcee5aeb1ac2412e90f41e45._openpgpkey.fedoraproject.org";
    assert_eq!(output, &email2domain(input).unwrap())
}