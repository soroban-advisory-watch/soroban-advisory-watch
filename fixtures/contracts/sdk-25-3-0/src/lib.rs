//! Test fixture built with soroban-sdk 25.3.0, which is outside the affected
//! ranges of every advisory bundled with this tool.
//! This contract is not meant to be deployed.
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Fixture;

#[contractimpl]
impl Fixture {
    pub fn hello(env: Env, to: Symbol) -> (Symbol, Symbol) {
        (Symbol::new(&env, "hello"), to)
    }
}
