use ink_prelude::vec::Vec;
use pink_extension as pink;
use pink::chain_extension::{signing, SigType};
use rlp::RlpStream;
use ethereum_types::{H160, H256, U256, U64};
use sha3::{Keccak256, Digest};

pub type Address = H160;
type Bytes = Vec<u8>;
const LEGACY_TX_ID: u64 = 0;

fn keccak_hash(x: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(x);
    hasher.finalize().into()
}

/// A transaction used for RLP encoding, hashing and signing.
pub struct Transaction {
    pub to: Option<Address>,
    pub nonce: U256,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub transaction_type: Option<U64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedTransaction {
    pub message_hash: H256,
    pub v: u64,
    pub r: H256,
    pub s: H256,
    pub raw_transaction: Bytes,   
    pub transaction_hash: H256,
}

pub struct Signature {
    /// V component in electrum format with chain-id replay protection.
    pub v: u64,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
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

    fn rlp_append_signature(&self, stream: &mut RlpStream, signature: &Signature) {
        stream.append(&signature.v);
        stream.append(&U256::from_big_endian(signature.r.as_bytes()));
        stream.append(&U256::from_big_endian(signature.s.as_bytes()));
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

    fn encode(&self, chain_id: u64, signature: Option<&Signature>) -> Vec<u8> {
        match self.transaction_type.map(|t|t.as_u64()) {
            Some(LEGACY_TX_ID) | None => {
                let stream = self.encode_legacy(chain_id, signature);
                stream.out().to_vec()
            }
            _ => {
                panic!("Unsupported transaction type");
            }
        }
    }

    pub fn sign(self, privkey: &[u8;32], chain_id: u64) -> SignedTransaction {
        let encoded = self.encode(chain_id, None);

        let msg_hash = keccak_hash(&encoded);

        let sign = signing::sign(&msg_hash, privkey, SigType::Ecdsa); 

        //EIP155: {0,1} + CHAIN_ID * 2 + 35 ???
        let recid:u64 = chain_id * 2 + 35;
        let signature = Signature {
            v: recid,
            r: H256::from_slice(&sign[..32]),
            s: H256::from_slice(&sign[32..]),
        };

        let signed = self.encode(chain_id, Some(&signature));

        let transaction_hash = keccak_hash(signed.as_ref()).into();

        SignedTransaction {
            message_hash: msg_hash.into(),
            v: signature.v,
            r: signature.r,
            s: signature.s,
            raw_transaction: signed.into(),
            transaction_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use pink::chain_extension::mock;

    #[test]
    fn sign_transaction_data() {

        let tx = Transaction {
            nonce: 0.into(),
            gas: 2_000_000.into(),
            gas_price: 234_567_897_654_321u64.into(),
            to: Some(hex!("F0109fC8DF283027b6285cc889F5aA624EaC1F55").into()),
            value: 1_000_000_000.into(),
            data: Vec::new(),
            transaction_type: None,
        };
        let skey = hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");

        mock::mock_sign(|_| {hex!("09ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9c440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428").to_vec()});
        let signed = tx.sign(&skey, 1);

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
