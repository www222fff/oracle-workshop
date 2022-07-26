#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};
    use ink_storage::traits::SpreadAllocate;
    use scale::{Decode, Encode};

    use secp256k1::{
        PublicKey, SecretKey,
    };
    use web3::types::Address;

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
    	secret_key: String,
    	public_key: String,
    	address: String,
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
            let account = generate_account();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                *this = account;
            })
        }


        #[ink(message)]
	pub fn get_address(&self) -> String {
            self.address.clone()
	}
    }

    fn generate_account() -> EthHolder {
        let random_bytes = pink::ext().getrandom(32);
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&random_bytes);
        let public = PublicKey::from_secret_key(&secp, &secret);

        let public_key_encode= public.serialize_uncompressed();
        debug_assert_eq!(public_key_encode[0], 0x04);
        let hash = keccak256(&public_key_encode[1..]);
        let addr = Address::from_slice(&hash[12..]);

        println!("secret key: {}", &secret.to_string());
        println!("public key: {}", &public.to_string());
        println!("address: {:?}", addr);

        EthHolder {
            secret_key: secret.to_string(),
            public_key: public.to_string(),
            address: format!("{:?}", addr),
        }
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
        fn get_account() {
            let accounts = default_accounts();

            let stack = SharedCallStack::new(accounts.alice);
            let ethHolder = Addressable::create_native(1, EthHolder::new(), stack.clone());

            //assert!(ethHolder.call_mut().get_address().is_ok());
	}
    }
}
