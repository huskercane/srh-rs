//! Shared contract-test fakes.

mod authenticator_contract;
mod executor_contract;
mod fake_executor;

pub use authenticator_contract::authenticator_contract;
pub use executor_contract::executor_contract;
pub use fake_executor::FakeExecutor;
