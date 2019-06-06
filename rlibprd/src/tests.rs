use crate::validator::Validator;
use crate::{KeyInfo, Validity};

static F29_GPGKEY: &'static str = "mQINBFqIZTcBEACjh0DKywPd0Hx9I4nGYsbUbqIU7TGZgxaT9jnVSRgkcdfRqt2C\
P7EdtRbyqkMUKyL23CLwAz+YSmf9Ff9nxBSl8FiKUCNNWUYO3faEAZkZ5reDr6h6\
W4a0niBMWfVLqmYjpZmkcBqgLgl+2wVq9/E9Fq9SzDktzczUF7wwAWrsKW5rwEEq\
+i8jk6FSUTNMqWZq69y7Dvox8k8QIxtou5dIL3Z8qQdkc/0ynTs4bdac94FsJBM6\
0qKSHP23MY7ppwOl7wttAsnaIzBaCD0UIM5qtfFBNFaYfeJ5kH1rf+NzgFjJ8y1D\
xiZdEX2t4OyXvhuAQSvYyotDrJzCbusjXQYMYYqnfGcqMmTCkgGxYbdfVGbMs3x1\
mMObZWMQbb9HGN0KTBaFdwA7EnMBrCGy3I9WxngGIGATOPWkPPUUxlaI9jwxT3tq\
bwYY5Kn2RhD4CZyj4VIaQvGdMaop01O78QVFHhdH24abqNuPrYqEDZ+aSTgnYFKJ\
cpGSsRVL+Kw/x1wik8PYzpC9tNzU1LRCi9jsX0pk9gODSgbKLWryZEgZaIdcBcJD\
4U3slDjdBeTDY8pJV9z9r7z+gFPAHLqStGKj2icbv80dMGTfgUm3HqWES/XXomX9\
ZWA1tV0ZlNOM8/IunmISz9MNpc3LChpcccffjrfvWBfokDKaXO9qCUgctwARAQAB\
tCxGZWRvcmEgMjkgKDI5KSA8ZmVkb3JhLTI5QGZlZG9yYXByb2plY3Qub3JnPokC\
OAQTAQIAIgUCWohlNwIbDwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQogql\
a0KUdrR7axAAluNHQ93T7u/yIQaTCs4uGb/jEg7qbm6hRx5nsqrdm3qKNqnyXK61\
nnPNoDJNk1WhZww4RdrvxCDOGyyNhGSejjvXM6RBDEOY/KmD6huPo8xN5i7JVG+E\
2mlwTGe7HSg47d0wHydDNTRLQqT0VZnpkxRe3puQ4DNNHJZG1SsRl/Sf2VI1XyB/\
hHbFGbLS9KvH32lCIAAtt6dbGTRZC9gsGL6XR/6o7EU5fpj7U5rYiDTFaYqmqG21\
LZZV9xtqCoHcKElY7jX7Rfmk8Wn1G2zC2XR0LX7eVH7GBeXw6JbmLZjxSgd235zE\
1lNSaSLMHOHMcgSHWoEC9ULzLYJuTagjK3cjk0VkKLocakRcsb9dtFcxgZGdQHfM\
X7mD9epuJmqB4a6TOZoL/tiq28ORakUbjYfLz9ngnqd/pJkn9MNWcxy3yBtOdTYq\
ce+61/XQk4cR2tH8V2eP7fL8YMboNkPPbcbKlcvKG/TgaS0tVrFMUmA1xmDihzf6\
gupAANlcMkYo0hm+z1hLvgqosp14oTocJeXLAFVw5dxnb9bmqjBy+77u/rqrY0Ek\
LQd9XnXgowUQl0RSNXgcIIfEkVBipL/2YB+MFBmMQKcTDXX7lc/hl6W4BFmVj2KH\
kPdZzUOJQVYfe90Rt3hfXHViUw118hkTaJhrCPVwkFbaUWscEA2OaFI=";

#[test]
fn resolve() {
    if let Ok(mut v) = Validator::try_new() {
        let key_info = KeyInfo {
            email: "fedora-29@fedoraproject.org".to_string(),
            b64_key: F29_GPGKEY.to_string(),
        };
        assert_eq!(v.validate(key_info), Validity::VALID);
    } else {
        panic!("Failed to initialize validator")
    }
}