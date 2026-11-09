//! Test fixture built with soroban-sdk 25.0.1, a version inside the affected
//! ranges of GHSA-96xm-fv9w-pf3f and GHSA-x2hw-px52-wp4m. It uses BLS12-381
//! `Fr` arithmetic so the Wasm imports a BLS12-381 host function.
//! This contract is not meant to be deployed.
#![no_std]
use soroban_sdk::{contract, contractimpl, crypto::bls12_381::Fr, Env, U256};

#[contract]
pub struct Fixture;

#[contractimpl]
impl Fixture {
    pub fn fr_sum(env: Env, a: U256, b: U256) -> U256 {
        let sum = Fr::from_u256(a) + Fr::from_u256(b);
        let _ = &env;
        sum.to_u256()
    }
}
