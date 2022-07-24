#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

use web3::types::{Address, TransactionReceipt, H160, H256, U128, U256};
use secp256k1::{PublicKey, SecretKey};

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
        admin: AccountId,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,

        ethAddress: Address,
        private_key: SecretKey,
        public_key: PublicKey,
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
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"gist-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
            })
        }


        #[ink(message)]
	fn generate_account() -> (SecretKey, PublicKey, Address) {
		let random_bytes = pink::ext().getrandom(32);
		//todo
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
        fn generate_account() {
            let accounts = default_accounts();

            let stack = SharedCallStack::new(accounts.alice);
            let ethHolder = Addressable::create_native(1, EthHolder::new(), stack.clone());
            assert_eq!(ethHolder.call().admin, accounts.alice);

            // Can add an issuer
            assert!(ethHolder.call_mut().generate_account().is_ok());
	}
    }
}
