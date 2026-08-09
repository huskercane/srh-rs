//! Shared contract-test fakes.

mod authenticator_contract;
mod executor_contract;
mod fake_executor;
mod fake_jwks;

pub use authenticator_contract::authenticator_contract;
pub use executor_contract::executor_contract;
pub use fake_executor::FakeExecutor;
pub use fake_jwks::FakeJwks;
