//! Partial implementation of the `Accounts` namespace.

use crate::{api::Namespace, signing, types::H256, Transport};


#[cfg(feature = "signing")]
mod accounts_signing {
    use super::*;
    use crate::{
        api::Web3,
        error,
        signing::Signature,
        types::{
            AccessList, Address, Bytes, Recovery, RecoveryMessage, SignedData, SignedTransaction,
            TransactionParameters, U256, U64,
        },
    };
    use rlp::RlpStream;
    use std::convert::TryInto;

    const LEGACY_TX_ID: u64 = 0;
    const ACCESSLISTS_TX_ID: u64 = 1;
    const EIP1559_TX_ID: u64 = 2;

    /// A transaction used for RLP encoding, hashing and signing.
    #[derive(Debug)]
    pub struct Transaction {
        pub to: Option<Address>,
        pub nonce: U256,
        pub gas: U256,
        pub gas_price: U256,
        pub value: U256,
        pub data: Vec<u8>,
        pub transaction_type: Option<U64>,
        pub access_list: AccessList,
        pub max_priority_fee_per_gas: U256,
    }

    impl Transaction {
        fn rlp_append_legacy(&self, stream: &mut RlpStream) {
            stream.append(&self.nonce);
            stream.append(&self.gas_price);
            stream.append(&self.gas);
            if let Some(to) = self.to {
                stream.append(&to);
            } else {
                stream.append(&"");
            }
            stream.append(&self.value);
            stream.append(&self.data);
        }

        fn encode_legacy(&self, chain_id: u64, signature: Option<&Signature>) -> RlpStream {
            let mut stream = RlpStream::new();
            stream.begin_list(9);

            self.rlp_append_legacy(&mut stream);

            if let Some(signature) = signature {
                self.rlp_append_signature(&mut stream, signature);
            } else {
                stream.append(&chain_id);
                stream.append(&0u8);
                stream.append(&0u8);
            }

            stream
        }

        fn encode_access_list_payload(&self, chain_id: u64, signature: Option<&Signature>) -> RlpStream {
            let mut stream = RlpStream::new();

            let list_size = if signature.is_some() { 11 } else { 8 };
            stream.begin_list(list_size);

            // append chain_id. from EIP-2930: chainId is defined to be an integer of arbitrary size.
            stream.append(&chain_id);

            self.rlp_append_legacy(&mut stream);
            self.rlp_append_access_list(&mut stream);

            if let Some(signature) = signature {
                self.rlp_append_signature(&mut stream, signature);
            }

            stream
        }

        fn encode_eip1559_payload(&self, chain_id: u64, signature: Option<&Signature>) -> RlpStream {
            let mut stream = RlpStream::new();

            let list_size = if signature.is_some() { 12 } else { 9 };
            stream.begin_list(list_size);

            // append chain_id. from EIP-2930: chainId is defined to be an integer of arbitrary size.
            stream.append(&chain_id);

            stream.append(&self.nonce);
            stream.append(&self.max_priority_fee_per_gas);
            stream.append(&self.gas_price);
            stream.append(&self.gas);
            if let Some(to) = self.to {
                stream.append(&to);
            } else {
                stream.append(&"");
            }
            stream.append(&self.value);
            stream.append(&self.data);

            self.rlp_append_access_list(&mut stream);

            if let Some(signature) = signature {
                self.rlp_append_signature(&mut stream, signature);
            }

            stream
        }

        fn rlp_append_signature(&self, stream: &mut RlpStream, signature: &Signature) {
            stream.append(&signature.v);
            stream.append(&U256::from_big_endian(signature.r.as_bytes()));
            stream.append(&U256::from_big_endian(signature.s.as_bytes()));
        }

        fn rlp_append_access_list(&self, stream: &mut RlpStream) {
            stream.begin_list(self.access_list.len());
            for access in self.access_list.iter() {
                stream.begin_list(2);
                stream.append(&access.address);
                stream.begin_list(access.storage_keys.len());
                for storage_key in access.storage_keys.iter() {
                    stream.append(storage_key);
                }
            }
        }

        fn encode(&self, chain_id: u64, signature: Option<&Signature>) -> Vec<u8> {
            match self.transaction_type.map(|t| t.as_u64()) {
                Some(LEGACY_TX_ID) | None => {
                    let stream = self.encode_legacy(chain_id, signature);
                    stream.out().to_vec()
                }

                Some(ACCESSLISTS_TX_ID) => {
                    let tx_id: u8 = ACCESSLISTS_TX_ID as u8;
                    let stream = self.encode_access_list_payload(chain_id, signature);
                    [&[tx_id], stream.as_raw()].concat()
                }

                Some(EIP1559_TX_ID) => {
                    let tx_id: u8 = EIP1559_TX_ID as u8;
                    let stream = self.encode_eip1559_payload(chain_id, signature);
                    [&[tx_id], stream.as_raw()].concat()
                }

                _ => {
                    panic!("Unsupported transaction type");
                }
            }
        }

        /// Sign and return a raw signed transaction.
        pub fn sign(self, sign: impl signing::Key, chain_id: u64) -> SignedTransaction {
            let adjust_v_value = matches!(self.transaction_type.map(|t| t.as_u64()), Some(LEGACY_TX_ID) | None);

            let encoded = self.encode(chain_id, None);

            let hash = signing::keccak256(encoded.as_ref());

            let signature = if adjust_v_value {
                sign.sign(&hash, Some(chain_id))
                    .expect("hash is non-zero 32-bytes; qed")
            } else {
                sign.sign_message(&hash).expect("hash is non-zero 32-bytes; qed")
            };

            let signed = self.encode(chain_id, Some(&signature));
            let transaction_hash = signing::keccak256(signed.as_ref()).into();

            SignedTransaction {
                message_hash: hash.into(),
                v: signature.v,
                r: signature.r,
                s: signature.s,
                raw_transaction: signed.into(),
                transaction_hash,
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{
        signing::{SecretKey, SecretKeyRef},
        transports::test::TestTransport,
        types::{Address, Recovery, SignedTransaction, TransactionParameters, U256},
    };
    use accounts_signing::*;
    use hex_literal::hex;
    use serde_json::json;

    #[test]
    fn sign_transaction_data() {
        // retrieved test vector from:
        // https://web3js.readthedocs.io/en/v1.2.2/web3-eth-accounts.html#eth-accounts-signtransaction

        let tx = Transaction {
            nonce: 0.into(),
            gas: 2_000_000.into(),
            gas_price: 234_567_897_654_321u64.into(),
            to: Some(hex!("F0109fC8DF283027b6285cc889F5aA624EaC1F55").into()),
            value: 1_000_000_000.into(),
            data: Vec::new(),
            transaction_type: None,
            access_list: vec![],
            max_priority_fee_per_gas: 0.into(),
        };
        let skey = SecretKey::from_slice(&hex!(
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        ))
        .unwrap();
        let key = SecretKeyRef::new(&skey);

        let signed = tx.sign(key, 1);

        let expected = SignedTransaction {
            message_hash: hex!("6893a6ee8df79b0f5d64a180cd1ef35d030f3e296a5361cf04d02ce720d32ec5").into(),
            v: 0x25,
            r: hex!("09ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9c").into(),
            s: hex!("440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428").into(),
            raw_transaction: hex!("f86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a009ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9ca0440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428").into(),
            transaction_hash: hex!("d8f64a42b57be0d565f385378db2f6bf324ce14a594afc05de90436e9ce01f60").into(),
        };

        assert_eq!(signed, expected);
    }
}
