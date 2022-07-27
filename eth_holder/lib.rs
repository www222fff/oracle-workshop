#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};
    use ink_storage::traits::SpreadAllocate;
    use scale::{Decode, Encode};

    use ink_prelude::{
        string::{String, ToString},
        vec::Vec,
        format,
    };

    use tiny_keccak::keccak256;
    use secp256k1::{Secp256k1, PublicKey, SecretKey};

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
    	secret_key: String,
    	public_key: String,
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
            self.secret_key.clone()
	}
    }

    fn generate_account() -> EthHolder {
        let sec_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let pub_key = PublicKey::from_slice(&[
    0x02,
    0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
    0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
    0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
    0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
        /*let random_bytes = pink::ext().getrandom(32);
        let secretKey = SecretKey::from_slice(&random_bytes).expect("32 bytes, within curve order");
        let secp = Secp256k1::new();
        let publicKey = PublicKey::from_secret_key(&secp, &secret);
        let public_key_encode= public.serialize_uncompressed();
        debug_assert_eq!(public_key_encode[0], 0x04);
        let hash = keccak256(&public_key_encode[1..]);
        let addr = Address::from_slice(&hash[12..]);
*/

        EthHolder {
            secret_key: format!("{}", sec_key.to_string()),
            public_key: pub_key.to_string(),
        }
    }


    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn get_address() {
           let account = generate_account();
           println!("secret key: {:?}", account);
	}
    }
}
