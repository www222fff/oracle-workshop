#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use ink_lang as ink;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use pink::logger::{Level, Logger};
    use pink::{http_get, http_post, PinkEnvironment};
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use scale::{Decode, Encode};
    use pink::chain_extension::signing as sig;
    use ink_prelude::{
        string::{String, ToString},
        vec::{Vec},
        format,
    };
    use ink_env::hash::{Keccak256, HashOutput};
    use core::convert::TryInto;
    pub use primitive_types::{U256, H256};
    use serde_json_core::from_slice;

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    type Address = [u8; 20];
    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;
    
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
    	private_key: Vec<u8>,
    	public_key: Vec<u8>,
        address: Address,

        rpc_nodes: Mapping<String, String>,
        chain_account_id: Mapping<String, String>,
        api_key: String,
        is_api_key_set: bool,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct NextNonce<'a> {
        jsonrpc: &'a str,
        result: u32,
        id: u32,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct TransactionParameters {
        /// Transaction nonce (None for account transaction count)
        pub nonce: Option<U256>,
        /// To address
        pub to: Option<Address>,
        /// Supplied gas
        pub gas: U256,
        /// Gas price (None for estimated gas price)
        pub gas_price: Option<U256>,
        /// Transferred value
        pub value: U256,
        /// Data
        //pub data: Bytes,
        /// The chain ID (None for network ID)
        pub chain_id: Option<u64>,
        /// Transaction type, Some(1) for AccessList transaction, None for Legacy
        //pub transaction_type: Option<U64>,
        /// Access list
        //pub access_list: Option<AccessList>,
        /// Max fee per gas
        pub max_fee_per_gas: Option<U256>,
        /// miner bribe
        pub max_priority_fee_per_gas: Option<U256>,
    }

    /// Data for offline signed transaction
    #[derive(Clone, Debug, PartialEq)]
        pub struct SignedTransaction {
        /// The given message hash
        pub message_hash: H256,
        /// V value with chain replay protection.
        pub v: u64,
        /// R value.
        pub r: H256,
        /// S value.
        pub s: H256,
        /// The raw signed transaction ready to be sent with `send_raw_transaction`
        //pub raw_transaction: Bytes,
        /// The transaction hash for the RLP encoded transaction.
        pub transaction_hash: H256,

    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidKeyLength,
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        NoPermissions,
        ApiKeyNotSet,
    }

    fn to_array<T>(v: &Vec<T>) -> [T; 33] where T: Copy {
        let slice = v.as_slice();
        let array: [T; 33] = slice.try_into().expect("Expected a Vec of length 33");
        array
    }

    impl EthHolder {
        #[ink(constructor)]
        pub fn new() -> Self {
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.api_key = Default::default();
                contract.is_api_key_set = false;
            })
        }
    
        #[ink(message)]
        fn generate_account(&self) -> Result<Address> {
            let privkey = pink::ext().getrandom(32);
            let pubkey = sig::get_public_key(&privkey, sig::SigType::Ecdsa);
            if  pubkey.len() != 33 {
                return Err(Error::InvalidKeyLength);
            }
           
            let mut address = [0; 20];
            let pubkey_array = to_array(&pubkey);
            ink_env::ecdsa_to_eth_address(&pubkey_array, &mut address);

            self.private_key = privkey;
            self.public_key = pubkey.to_vec();
            self.address = address;
            Ok(self.address)
        }

        /// Set the RPC node for parachain.
        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String, account_id: String) -> Result<()> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            if !self.is_api_key_set {
                return Err(Error::ApiKeyNotSet);
            }

            let http_endpoint = format!(
                "https://{}.infura.io/v3/{}",
                chain, self.api_key
            );
            self.rpc_nodes.insert(&chain, &http_endpoint);
            self.chain_account_id.insert(&chain, &account_id);
            Ok(())
        }

        /// Set the user api key for user account.
        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> Result<()> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
          */  }
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        /// Get account's next nonce on a specific chain.
        #[ink(message)]
        pub fn get_next_nonce(&self, chain: String) -> Result<u32> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let data = format!(
                r#"{{"id":0,"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{}"]}}"#,
                account_id
            )
            .into_bytes();
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = response.body;
            let (next_nonce, _): (NextNonce, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidBody))?;

            Ok(next_nonce.result)
        }

/*        #[ink(message)]
        pub fn send_rawTransaction(&self, chain: String, to: Address, nonce: U256, value: U256) -> Result<()> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let account_id = match self.chain_account_id.get(&chain) {
                Some(account_id) => account_id,
                None => return Err(Error::ChainNotConfigured),
            };
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };

            //todo create tx.

            let data = format!(
                r#"{{"id":0,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"]}}"#,
                account_id
            )
            .into_bytes();
            let content_length = format!("{}", data.len());
            let headers: Vec<(String, String)> = vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), content_length),
            ];
            // Get next nonce for the account through HTTP request
            let response = http_post!(rpc_node, data, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            Ok(());
        }*/
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use pink_extension::chain_extension::{mock};

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn end_to_end() {
            use openbrush::traits::mock::{Addressable, SharedCallStack};

            // Test accounts
            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);

            mock_issuable::using(stack.clone(), || {
                // Construct our contract (deployed by `accounts.alice` by default)
                let contract = Addressable::create_native(1, EthHolder::new(), stack);

            mock::mock_getrandom(|_| {
                [0x9e,0xb2,0xee,0x60,0x39,0x3a,0xee,0xec,
                0x31,0x70,0x9e,0x25,0x6d,0x44,0x8c,0x9e,
                0x40,0xfa,0x64,0x23,0x3a,0xbf,0x12,0x31,
                0x8f,0x63,0x72,0x6e,0x9c,0x41,0x7b,0x69].to_vec()
            });

            mock::mock_get_public_key(|_| {
                [0x02,0x62,0x20,0x26,0x8e,0x36,0xda,0x1d,
                0x79,0x9a,0x67,0xc3,0xac,0x5e,0xca,0xc2,
                0x24,0xb4,0x5c,0xea,0x2b,0x04,0x7d,0x1b,
                0x68,0xa8,0xff,0xbf,0x31,0xf0,0x8b,0x27,0x50].to_vec()
           });

           let account = contract.call().generate_account().unwrap();
           println!("account: {:?}", account);

           let EXPECTED_ETH_ADDRESS = [0x55,0x9b,0xfe,0xc7,0x5a,0xd4,0x0e,0x4f,
                                       0xf2,0x18,0x19,0xbc,0xd1,0xf6,0x58,0xcc,
                                       0x47,0x5c,0x41,0xba]; 
           assert_eq!(account.address, EXPECTED_ETH_ADDRESS);
	}
    }
}
