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
    use web3::{
        types::{Address, TransactionParameters, H256, U256},
    };


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
        let sec_key = SecretKey::from_slice(&random_bytes).expect("32 bytes, within curve order");
        let secp = Secp256k1::new();
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        let public_key_encode= pub_key.serialize_uncompressed();
        debug_assert_eq!(public_key_encode[0], 0x04);
        let hash = keccak256(&public_key_encode[1..]);
        let addr = Address::from_slice(&hash[12..]);

        EthHolder {
            secret_key: format!("{}", sec_key.to_string()),
            public_key: pub_key.to_string(),
            address: format!("{:?}", addr),
        }
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
        fn get_address() {
           mock::mock_getrandom(|_| {
               //[0xcd; 32].to_vec()
               [0x9e,0xb2,0xee,0x60,0x39,0x3a,0xee,0xec,
                0x31,0x70,0x9e,0x25,0x6d,0x44,0x8c,0x9e,
                0x40,0xfa,0x64,0x23,0x3a,0xbf,0x12,0x31,
                0x8f,0x63,0x72,0x6e,0x9c,0x41,0x7b,0x69].to_vec()
           });

           let account = generate_account();
           println!("account: {:?}", account);

           let EXPECTED_ETH_ADDRESS = "0x559bfec75ad40e4ff21819bcd1f658cc475c41ba"; 
           assert_eq!(account.address, EXPECTED_ETH_ADDRESS);
	}
    }
}
