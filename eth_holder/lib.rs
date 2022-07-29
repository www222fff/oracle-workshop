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
    use pink::chain_extension::signing as sig;
    use ink_prelude::{
        string::{String, ToString},
        vec::{Vec},
        format,
    };
    use ink_env::hash::{Keccak256, HashOutput};
    use core::convert::TryInto;

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    type Address = [u8; 20];

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
    	private_key: Vec<u8>,
    	public_key: Vec<u8>,
        address: Address,
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
	pub fn get_address(&self) -> Address {
            self.address
	}
    }

    
    fn to_array<T>(v: &Vec<T>) -> [T; 33] where T: Copy {
        let slice = v.as_slice();
        let array: [T; 33] = slice.try_into().expect("Expected a Vec of length 33");
        array
    }

    fn generate_account() -> EthHolder {
        let privkey = pink::ext().getrandom(32);
        let pubkey = sig::get_public_key(&privkey, sig::SigType::Ecdsa);
        let mut address = [0; 20];
        let pubkey_array = to_array(&pubkey);
        ink_env::ecdsa_to_eth_address(&pubkey_array, &mut address);

        EthHolder {
            private_key: privkey,
            public_key: pubkey.to_vec(),
            address: address,
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
        fn get_account() {
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

           let account = generate_account();
           println!("account: {:?}", account);

           let EXPECTED_ETH_ADDRESS = [0x55,0x9b,0xfe,0xc7,0x5a,0xd4,0x0e,0x4f,
                                       0xf2,0x18,0x19,0xbc,0xd1,0xf6,0x58,0xcc,
                                       0x47,0x5c,0x41,0xba]; 
           assert_eq!(account.address, EXPECTED_ETH_ADDRESS);
	}
    }
}
