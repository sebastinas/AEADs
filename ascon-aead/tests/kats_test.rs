// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use ascon_aead::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    Ascon128, Ascon128a, Ascon80pq, Key, Nonce,
};
use std::collections::HashMap;
use std::include_str;

#[derive(Debug)]
struct TestVector {
    count: u32,
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl TestVector {
    fn new(
        count: &str,
        key: &str,
        nonce: &str,
        plaintext: &str,
        associated_data: &str,
        ciphertext: &str,
    ) -> Self {
        Self {
            count: count.parse().unwrap(),
            key: hex::decode(key).unwrap(),
            nonce: hex::decode(nonce).unwrap(),
            plaintext: hex::decode(plaintext).unwrap(),
            associated_data: hex::decode(associated_data).unwrap(),
            ciphertext: hex::decode(ciphertext).unwrap(),
        }
    }
}

fn run_tv2<A: KeyInit + AeadInPlace>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) {
    let core = A::new(Key::<A>::from_slice(key));
    let ctxt = core
        .encrypt(
            Nonce::<A>::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("Successful encryption");
    assert_eq!(ctxt, ciphertext);

    let ptxt = core
        .decrypt(
            Nonce::<A>::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .expect("Successful decryption");
    assert_eq!(ptxt, plaintext);
}

fn run_tv<A: KeyInit + AeadInPlace>(tv: TestVector) {
    run_tv2::<A>(
        &tv.key,
        &tv.nonce,
        &tv.plaintext,
        &tv.associated_data,
        &tv.ciphertext,
    )
}

fn parse_tvs(tvs: &str) -> Vec<TestVector> {
    let mut fields: HashMap<String, String> = HashMap::new();
    let mut ret = Vec::new();

    for line in tvs.lines() {
        if line.is_empty() && !fields.is_empty() {
            ret.push(TestVector::new(
                &fields["Count"],
                &fields["Key"],
                &fields["Nonce"],
                &fields["PT"],
                &fields["AD"],
                &fields["CT"],
            ));
            fields.clear();
            continue;
        }

        let mut values = line.split(" = ");
        fields.insert(
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        );
    }

    assert!(!ret.is_empty(), "Test vectors available.");
    ret
}

#[test]
fn test_vectors_ascon128() {
    let tvs = parse_tvs(include_str!("data/ascon128.txt"));
    for tv in tvs {
        run_tv::<Ascon128>(tv);
    }
}

#[test]
fn test_vectors_ascon128a() {
    let tvs = parse_tvs(include_str!("data/ascon128a.txt"));
    for tv in tvs {
        run_tv::<Ascon128a>(tv);
    }
}

#[test]
fn test_vectors_ascon80pq() {
    let tvs = parse_tvs(include_str!("data/ascon80pq.txt"));
    for tv in tvs {
        run_tv::<Ascon80pq>(tv);
    }
}
