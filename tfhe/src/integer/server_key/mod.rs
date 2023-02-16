//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
pub mod comparator;
mod crt;
mod crt_parallel;
mod radix;
mod radix_parallel;

use crate::integer::client_key::ClientKey;
use crate::shortint::server_key::MaxDegree;
use serde::{Deserialize, Serialize};

/// Error returned when the carry buffer is full.
pub use crate::shortint::CheckError;

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic integer circuits.
#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey {
    pub(crate) key: crate::shortint::ServerKey,
}

impl From<ServerKey> for crate::shortint::ServerKey {
    fn from(key: ServerKey) -> crate::shortint::ServerKey {
        key.key
    }
}

impl ServerKey {
    /// Generates a server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new(&cks);
    /// ```
    pub fn new<C>(cks: C) -> ServerKey
    where
        C: AsRef<ClientKey>,
    {
        // It should remain just enough space to add a carry
        let client_key = cks.as_ref();
        let max = (client_key.key.parameters.message_modulus.0 - 1)
            * client_key.key.parameters.carry_modulus.0
            - 1;

        let sks = crate::shortint::server_key::ServerKey::new_with_max_degree(
            &client_key.key,
            MaxDegree(max),
        );

        ServerKey { key: sks }
    }

    /// Creates a ServerKey from an already generated shortint::ServerKey.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new(&cks);
    /// ```
    pub fn from_shortint(
        cks: &ClientKey,
        mut key: crate::shortint::server_key::ServerKey,
    ) -> ServerKey {
        // It should remain just enough space add a carry
        let max =
            (cks.key.parameters.message_modulus.0 - 1) * cks.key.parameters.carry_modulus.0 - 1;

        key.max_degree = MaxDegree(max);
        ServerKey { key }
    }
}
