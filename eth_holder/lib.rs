#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn attest(&self, arg: String) -> Result<attestation::Attestation, Vec<u8>>;
}

#[pink::contract(env=PinkEnvironment)]
mod eth_holder {
    use super::pink;
    use super::SubmittableOracle;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};

    use fat_utils::attestation;
    use ink_prelude::{
        string::{String, ToString},
        vec::Vec,
    };
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use scale::{Decode, Encode};

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EthHolder {
        admin: AccountId,
        eth_holders: AccountId,
        private_key: AccountId,
        public_key: AccountId,
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
                this.badge_contract_options = None;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
            })
        }


        #[ink(message)]
	fn generate_account() -> (H256, PrivateKey, Account) {
		let default_balance = 1_000_000u32.into();

		let rng = &mut thread_rng();
		let sk = priv_key_from_fs(rng.gen());

		let eth_sk = H256::random();
		let address = PackedEthSignature::address_from_private_key(&eth_sk)
			.expect("Can't get address from the ETH secret key");

		let mut account = Account::default_with_address(&address);
		account.pub_key_hash = PubKeyHash::from_privkey(&sk);
		account.set_balance(ETH_TOKEN_ID, default_balance);

		(eth_sk, sk, account)
	}

    }

    impl SubmittableOracle for EthHolder {
        // Queries

        /// Attests a Github Gist by the raw file url. (Query only)
        ///
        /// It sends a HTTPS request to the url and extract an address from the claim ("This gist
        /// is owned by address: 0x..."). Once the claim is verified, it returns a signed
        /// attestation with the data `(username, account_id)`.
        ///
        /// The `Err` variant of the result is an encoded `Error` to simplify cross-contract calls.
        /// Particularly, when another contract wants to call us, they may not want to depend on
        /// any special type defined by us (`Error` in this case). So we only return generic types.
        #[ink(message)]
        fn attest(&self, url: String) -> core::result::Result<attestation::Attestation, Vec<u8>> {
            // Verify the URL
            let gist_url = parse_gist_url(&url).map_err(|e| e.encode())?;
            // Fetch the gist content
            let resposne = http_get!(url);
            if resposne.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            let body = resposne.body;
            // Verify the claim and extract the account id
            let account_id = extract_claim(&body).map_err(|e| e.encode())?;
            let quote = GistQuote {
                username: gist_url.username,
                account_id,
            };
            let result = self.attestation_generator.sign(quote);
            Ok(result)
        }

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }
    }

    #[derive(PartialEq, Eq, Debug)]
    struct GistUrl {
        username: String,
        gist_id: String,
        filename: String,
    }

    #[derive(Clone, Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct GistQuote {
        username: String,
        account_id: AccountId,
    }

    /// Parses a Github Gist url.
    ///
    /// - Returns a parsed [GistUrl] struct if the input is a valid url;
    /// - Otherwise returns an [Error].
    fn parse_gist_url(url: &str) -> Result<GistUrl> {
        let path = url
            .strip_prefix("https://gist.githubusercontent.com/")
            .ok_or(Error::InvalidUrl)?;
        let components: Vec<_> = path.split('/').collect();
        if components.len() < 5 {
            return Err(Error::InvalidUrl);
        }
        Ok(GistUrl {
            username: components[0].to_string(),
            gist_id: components[1].to_string(),
            filename: components[4].to_string(),
        })
    }

    const CLAIM_PREFIX: &str = "This gist is owned by address: 0x";
    const ADDRESS_LEN: usize = 64;

    /// Extracts the ownerhip of the gist from a claim in the gist body.
    ///
    /// A valid claim must have the statement "This gist is owned by address: 0x..." in `body`. The
    /// address must be the 256 bits public key of the Substrate account in hex.
    ///
    /// - Returns a 256-bit `AccountId` representing the owner account if the claim is valid;
    /// - otherwise returns an [Error].
    fn extract_claim(body: &[u8]) -> Result<AccountId> {
        let body = String::from_utf8_lossy(body);
        let pos = body.find(CLAIM_PREFIX).ok_or(Error::NoClaimFound)?;
        let addr: String = body
            .chars()
            .skip(pos)
            .skip(CLAIM_PREFIX.len())
            .take(ADDRESS_LEN)
            .collect();
        let addr = addr.as_bytes();
        let account_id = decode_accountid_256(addr)?;
        Ok(account_id)
    }

    /// Decodes a hex string as an 256-bit AccountId32
    fn decode_accountid_256(addr: &[u8]) -> Result<AccountId> {
        use hex::FromHex;
        if addr.len() != ADDRESS_LEN {
            return Err(Error::InvalidAddressLength);
        }
        let bytes = <[u8; 32]>::from_hex(addr).or(Err(Error::InvalidAddress))?;
        Ok(AccountId::from(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn can_parse_gist_url() {
            let result = parse_gist_url("https://gist.githubusercontent.com/h4x3rotab/0cabeb528bdaf30e4cf741e26b714e04/raw/620f958fb92baba585a77c1854d68dc986803b4e/test%2520gist");
            assert_eq!(
                result,
                Ok(GistUrl {
                    username: "h4x3rotab".to_string(),
                    gist_id: "0cabeb528bdaf30e4cf741e26b714e04".to_string(),
                    filename: "test%2520gist".to_string(),
                })
            );
            let err = parse_gist_url("http://example.com");
            assert_eq!(err, Err(Error::InvalidUrl));
        }

        #[ink::test]
        fn can_decode_claim() {
            let ok = extract_claim(b"...This gist is owned by address: 0x0123456789012345678901234567890123456789012345678901234567890123...");
            assert_eq!(
                ok,
                decode_accountid_256(
                    b"0123456789012345678901234567890123456789012345678901234567890123"
                )
            );
            // Bad cases
            assert_eq!(
                extract_claim(b"This gist is owned by"),
                Err(Error::NoClaimFound),
            );
            assert_eq!(
                extract_claim(b"This gist is owned by address: 0xAB"),
                Err(Error::InvalidAddressLength),
            );
            assert_eq!(
                extract_claim(b"This gist is owned by address: 0xXX23456789012345678901234567890123456789012345678901234567890123"),
                Err(Error::InvalidAddress),
            );
        }

        #[ink::test]
        fn end_to_end() {
            use pink_extension::chain_extension::{mock, HttpResponse};
            fat_utils::test_helper::mock_all();

            // Test accounts
            let accounts = default_accounts();

            use openbrush::traits::mock::{Addressable, SharedCallStack};

            let stack = SharedCallStack::new(accounts.alice);
        }
    }
}
