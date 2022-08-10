#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use pink::{http_post, PinkEnvironment};
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use scale::{Decode, Encode};
    use pink::chain_extension::signing as sig;
    use ink_prelude::{
        string::{String, ToString},
        vec::{Vec},
        vec,
        format,
    };
    use serde::Deserialize;
    use serde_json_core::from_slice;
    use core::fmt::Write;
    use hex::FromHex;

    pub use primitive_types::{U256, H256};

    type Address = [u8; 20];
    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;
    
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
        admin: AccountId,
    	private_key: Vec<u8>,
    	public_key: Vec<u8>,
        address: Address,

        rpc_nodes: Mapping<String, String>,
        chain_account_id: Mapping<String, String>,
        api_key: String,
        is_api_key_set: bool,
    }

    #[derive(Deserialize, Encode, Clone, Debug, PartialEq)]
    pub struct RpcResult<'a> {
        jsonrpc: &'a str,
        result: &'a str,
        id: u32,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        InvalidKey,
        InvalidBody,
        InvalidUrl,
        InvalidSignature,
        RequestFailed,
        NoPermissions,
        ChainNotConfigured,
        ApiKeyNotSet,
    }

    fn vec_to_array<T>(v: &Vec<T>) -> [T; 33] where T: Copy {
        let slice = v.as_slice();
        let array: [T; 33] = slice.try_into().expect("Expected a Vec of length 33");
        array
    }

    fn vec_to_hex_string(v: &Vec<u8>) -> String {
        let mut res = "0x".to_string();        
        for a in v.iter() {
            write!(res, "{:02x}", a);
        }
        res
    }

    fn call_rpc(rpc_node: &String, data: Vec<u8>) -> Result<String> {
        let content_length = format!("{}", data.len());
        let headers: Vec<(String, String)> = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), content_length),
        ];

        let response = http_post!(rpc_node, data, headers);
        if response.status_code != 200 {
            return Err(Error::RequestFailed);
        }
        let body = response.body;
        let (rpc_res, _): (RpcResult, usize) = from_slice(&body).or(Err(Error::InvalidBody))?;
        
        let result = rpc_res.result.to_string();
        Ok(result)
    }

    fn get_next_nonce(rpc_node: &String, account: Address) -> u64 {
        let account_str = vec_to_hex_string(&account.to_vec());
        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{:?}", "latest"]}}"#,
            account_str
        )
        .into_bytes();

        let result = call_rpc(rpc_node, data).unwrap();
        let nonce:String = result.chars().skip(2).collect();
        u64::from_str_radix(&nonce, 16).unwrap()
    }
    
    fn get_gas_price(rpc_node: &String) -> u64 {
        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_gasPrice","params":[]}}"#
        )
        .into_bytes();

        let result = call_rpc(rpc_node, data).unwrap();
        let gas_price:String = result.chars().skip(2).collect();
        u64::from_str_radix(&gas_price, 16).unwrap()
    }

    fn send_raw_transaction(rpc_node: &String, raw_tx: Vec<u8>) -> String {
        let raw_tx_str = vec_to_hex_string(&raw_tx);

        let data = format!(
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{:?}"]}}"#,
            raw_tx_str
        )
        .into_bytes();

        let tx_res = call_rpc(rpc_node, data).unwrap();
        tx_res
    }

    impl EthHolder {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.api_key = Default::default();
                contract.is_api_key_set = false;
            })
        }
    
        #[ink(message)]
        pub fn generate_account(&mut self) -> Result<Address> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let privkey = pink::ext().getrandom(32);
            let pubkey = sig::get_public_key(&privkey, sig::SigType::Ecdsa);
            if  pubkey.len() != 33 {
                return Err(Error::InvalidKey);
            }
           
            let mut address = [0; 20];
            let pubkey_array = vec_to_array(&pubkey);
            ink_env::ecdsa_to_eth_address(&pubkey_array, &mut address).or(Err(Error::InvalidKey))?;

            self.private_key = privkey;
            self.public_key = pubkey.to_vec();
            self.address = address;
            Ok(address)
        }

        #[ink(message)]
        pub fn get_account(&self) -> String {
            format!("privKey:{:?},pubkey:{:?},address:{:?}", self.private_key, self.public_key, self.address)
        }

        #[ink(message)]
        pub fn set_api_key(&mut self, api_key: String) -> Result<()> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String) -> Result<()> {
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
            Ok(())
        }

        #[ink(message)]
        pub fn send_transaction(&self, chain: String, to: Address, value: U256) -> Result<String> {
            if self.admin != self.env().caller() {
                return Err(Error::NoPermissions);
            }
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };

            //step1: get nonce and gas_price.
            let nonce = get_next_nonce(&rpc_node, self.address);
            let gas_price = get_gas_price(&rpc_node);


            /* TBD
            let tx = TransactionObj {
                to,
                value,
                nonce,
                gas,
                gas_price,
            };
            //step2: sign tx.
            let signTx = sign_transaction(&tx, &self.private_key).unwrap();

            //step3: send raw transaction 
            let txHash = send_raw_transaction(&signTx.raw_transaction);
            */

            Ok("txHash".to_string())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};
        use pink_extension::chain_extension::{mock, HttpResponse};
        use hex_literal::hex;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn verify_get_next_nonce() {
            let rpc_node = "https://mainnet.infura.io/v3/2033e5cde24049d4a933778ffefe2457".to_string();
            let addr = hex!("559bfec75ad40e4ff21819bcd1f658cc475c41ba"); 

            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x8B"}"#.to_vec())
            });
            let nonce = get_next_nonce(&rpc_node, addr);
            println!("nonce: {}", nonce);
            assert_eq!(nonce, 0x8B);

        }

        #[ink::test]
        fn verify_get_gas_price() {
            let rpc_node = "https://mainnet.infura.io/v3/2033e5cde24049d4a933778ffefe2457".to_string();

            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x1dfd14000"}"#.to_vec())
            });
            let gas_price = get_gas_price(&rpc_node);
            println!("gas_price: {}", gas_price);
            assert_eq!(gas_price, 8049999872);

        }

        #[ink::test]
        fn end_to_end() {
            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);

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

           let contract = Addressable::create_native(1, EthHolder::new(), stack.clone());
           let account = contract.call_mut().generate_account().unwrap();
           println!("account: {:?}", account);

           let EXPECTED_ETH_ADDRESS = hex!("559bfec75ad40e4ff21819bcd1f658cc475c41ba");
           assert_eq!(account, EXPECTED_ETH_ADDRESS);
        }
    }
}
