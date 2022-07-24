#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

use crate::utils;
use secp256k1::{rand::rngs, PublicKey, SecretKey};
use web3::{
    transports,
    types::{Address, TransactionParameters, H256, U256},
    Web3,
};


#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};

    use scale::{Decode, Encode};

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
    	pub secret_key: String,
    	pub public_key: String,
    	pub address: String,
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        BadgeContractNotSetUp,
        InvalidUrl,
        RequestFailed,
        NoClaimFound,
        InvalidAddressLength,
        InvalidAddress,
        NoPermission,
        InvalidSignature,
        UsernameAlreadyInUse,
        AccountAlreadyInUse,
        FailedToIssueBadge,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl EthHolder {
        #[ink(constructor)]
        pub fn new() -> Self {
            let (secret_key, pub_key) = generate_keypair();
            let addr = public_key_address(&pub_key);

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.secret_key = format!("{}", secret_key.to_string());
                this.public_key = public_key.to_string();
                this.address = format!("{:?}", addr);
            })
        }


        #[ink(message)]
	fn show_account(&self) -> Address {
            println!("secret key: {}", &self.secret_key);
            println!("public key: {}", &self.pub_key);
            println!("address: {:?}", &self.address);
            self.address.clone()
	}
    }

    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rngs::JitterRng::new_with_timer(utils::get_nstime);
        secp.generate_keypair(&mut rng)
    }

    pub fn public_key_address(public_key: &PublicKey) -> Address {
        let public_key = public_key.serialize_uncompressed();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);

        Address::from_slice(&hash[12..])
    }


    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};

        fn default_accounts() -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn show_eth_account() {
            let accounts = default_accounts();

            let stack = SharedCallStack::new(accounts.alice);
            let ethHolder = Addressable::create_native(1, EthHolder::new(), stack.clone());

            assert!(ethHolder.call_mut().show_account().is_ok());
	}
    }
}
