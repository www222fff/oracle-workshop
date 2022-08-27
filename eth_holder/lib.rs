#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use pink_extension as pink;
use hex_literal::hex;
use fat_utils::transaction;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::*;
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
    use fat_utils::transaction;

    type Address = [u8; 20];
    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;
    
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
        rpc_nodes: Mapping<String, String>,
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

    pub fn derive_account(salt: &[u8]) -> Result<([u8; 32], [u8; 33], Address)> {
        let privkey_sr25519 = sig::derive_sr25519_key(salt);
        let privkey: [u8; 32] = privkey_sr25519[0..32].try_into().expect("Expected a Vec of length 32");
        let pubkey: [u8; 33] = sig::get_public_key(&privkey, sig::SigType::Ecdsa).try_into().expect("Expected a Vec of length 33");
        let mut address = [0; 20];
        ink_env::ecdsa_to_eth_address(&pubkey, &mut address).or(Err(Error::InvalidKey))?;

        Ok((privkey, pubkey, address))
    }

    fn get_chain_id(chain: String) -> u64 {
        if chain == "mainnet" { 1 }
        else if chain == "rinkeby" { 4 }
        else { 0 }
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
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_getTransactionCount","params":[{:?}, "latest"]}}"#,
            account_str
        );

        let result = call_rpc(rpc_node, data.into_bytes()).unwrap();
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
            r#"{{"id":0,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":[{:?}]}}"#,
            raw_tx_str
        )
        .into_bytes();

        let tx_res = call_rpc(rpc_node, data).unwrap();
        tx_res
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
        pub fn set_api_key(&mut self, api_key: String) -> Result<()> {
            self.api_key = api_key;
            self.is_api_key_set = true;
            Ok(())
        }

        #[ink(message)]
        pub fn set_chain_info(&mut self, chain: String) -> Result<()> {
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
        pub fn send_transaction(&self, chain: String, to: Address, value: u64) -> Result<String> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };

            //step1: get nonce and gas_price.
            let caller = Self::env().caller();
            let salt = caller.as_ref();
            let (privKey, _, address) = derive_account(salt).unwrap();
            let nonce = get_next_nonce(&rpc_node, address);
            let gas_price = get_gas_price(&rpc_node);


            let tx = transaction::Transaction {
                nonce: nonce.into(),
                gas: 2_000_000.into(),
                gas_price: gas_price.into(),
                to: Some(to.into()),
                value: value.into(),
                data: Vec::new(),
                transaction_type: None,
            };

            //step2: sign tx.
            let signTx: transaction::SignedTransaction = tx.sign(&privKey, get_chain_id(chain));

            //step3: send raw transaction 
            let txHash = send_raw_transaction(&rpc_node, signTx.raw_transaction);
            Ok(txHash)

            /*debug
            let tx = transaction::Transaction {
                nonce: 0.into(),
                gas: 2_000_000.into(),
                gas_price: 234_567_897_654_321u64.into(),
                to: Some(hex!("F0109fC8DF283027b6285cc889F5aA624EaC1F55").into()),
                value: 1_000_000_000.into(),
                data: Vec::new(),
                transaction_type: None,
            };
            let skey = hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
            let signTx = tx.sign(&skey, 1);
            Ok(signTx)*/
        }

        #[ink(message)]
        pub fn get_account(&self) -> Result<([u8; 32], [u8; 33], Address)> {
            let caller = Self::env().caller();
            let salt: &[u8]= caller.as_ref();
            let (privkey, pubkey, address) = derive_account(salt).unwrap();
            Ok((privkey, pubkey, address))
        }

        #[ink(message)]
        pub fn get_nonce(&self, chain: String) -> Result<u64> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let caller = Self::env().caller();
            let salt = caller.as_ref();
            let (_, _, address) = derive_account(salt).unwrap();
            let nonce = get_next_nonce(&rpc_node, address);
            Ok(nonce)
        }

        #[ink(message)]
        pub fn get_gas_price(&self, chain: String) -> Result<u64> {
            let rpc_node = match self.rpc_nodes.get(&chain) {
                Some(rpc_node) => rpc_node,
                None => return Err(Error::ChainNotConfigured),
            };
            let gas_price = get_gas_price(&rpc_node);
            Ok(gas_price)
        }

    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};
        use pink::chain_extension::{mock, HttpResponse};

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn end_to_end() {
            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);
            let contract = Addressable::create_native(1, EthHolder::new(), stack.clone());

            //generate account
            mock::mock_derive_sr25519_key(|_| {hex!("9eb2ee60393aeeec31709e256d448c9e40fa64233abf12318f63726e9c417b69").to_vec()});
            mock::mock_get_public_key(|_| {hex!("026220268e36da1d799a67c3ac5ecac224b45cea2b047d1b68a8ffbf31f08b2750").to_vec()});
            let (privkey, pubkey, address) = derive_account(b"eth-holder").unwrap();
            println!("addr: {:?}", address);
            let expect_addr = hex!("559bfec75ad40e4ff21819bcd1f658cc475c41ba");
            assert_eq!(address, expect_addr);

            //construct chain uri
            let api_key = "2033e5cde24049d4a933778ffefe2457";
            let chain = "rinkeby";
            contract.call_mut().set_api_key(api_key.to_string());
            contract.call_mut().set_chain_info(chain.to_string());

            //get nonce
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x8B"}"#.to_vec())
            });
            let nonce = contract.call().get_nonce(chain.to_string()).unwrap();
            println!("nonce: {}", nonce);
            assert_eq!(nonce, 0x8B);

            //get gas price
            mock::mock_http_request(|_| {
                HttpResponse::ok(br#"{"jsonrpc":"2.0","id":1,"result":"0x1dfd14000"}"#.to_vec())
            });
            let gas_price = contract.call().get_gas_price(chain.to_string()).unwrap();
            println!("gas_price: {}", gas_price);
            assert_eq!(gas_price, 8049999872);
        }
    }
}
