// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Private implementation details of Subspace consensus digests.

use super::{FarmerSignature, Slot, SubspaceEpochConfiguration, SUBSPACE_ENGINE_ID};
use crate::FarmerPublicKey;
use codec::{Codec, Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{DigestItem, RuntimeDebug};
use sp_std::vec::Vec;
use subspace_core_primitives::Randomness;

// TODO: better documentation here
/// Solution
#[derive(Clone, RuntimeDebug, Encode, Decode)]
pub struct Solution {
    /// Public key of the farmer that created solution
    pub public_key: FarmerPublicKey,
    /// Index of encoded piece
    pub piece_index: u64,
    /// Encoding
    pub encoding: Vec<u8>,
    /// Signature of the tag
    pub signature: Vec<u8>,
    /// Tag (hmac of encoding and salt)
    pub tag: [u8; 8],
}

impl Solution {
    /// Dummy solution for the genesis block
    pub fn get_for_genesis() -> Self {
        Self {
            public_key: FarmerPublicKey::default(),
            piece_index: 0u64,
            encoding: Vec::new(),
            signature: Vec::new(),
            tag: [0u8; 8],
        }
    }
}

/// A Subspace pre-runtime digest. This contains all data required to validate a block and for the
/// Subspace runtime module.
#[derive(Clone, RuntimeDebug, Encode, Decode)]
pub struct PreDigest {
    /// Slot
    pub slot: Slot,
    /// Solution (includes PoR)
    pub solution: Solution,
}

impl PreDigest {
    /// Returns the weight _added_ by this digest, not the cumulative weight
    /// of the chain.
    pub fn added_weight(&self) -> crate::SubspaceBlockWeight {
        1
    }
}

/// Information about the next epoch. This is broadcast in the first block
/// of the epoch.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct NextEpochDescriptor {
    /// The value of randomness to use for the slot-assignment.
    pub randomness: Randomness,
}

/// Information about the next epoch config, if changed. This is broadcast in the first
/// block of the epoch, and applies using the same rules as `NextEpochDescriptor`.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug, TypeInfo)]
pub enum NextConfigDescriptor {
    /// Version 1.
    #[codec(index = 1)]
    V1 {
        /// Value of `c` in `SubspaceEpochConfiguration`.
        c: (u64, u64),
    },
}

impl From<NextConfigDescriptor> for SubspaceEpochConfiguration {
    fn from(desc: NextConfigDescriptor) -> Self {
        match desc {
            NextConfigDescriptor::V1 { c } => Self { c },
        }
    }
}

/// Information about the solution range for the block.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct SolutionRangeDescriptor {
    /// Solution range used for challenges.
    pub solution_range: u64,
}

/// Salt for the block.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct SaltDescriptor {
    /// Salt used with challenges.
    pub salt: u64,
}

/// Information about the solution range, if changed. This is broadcast in the first
/// block of the era, but only applies to the block after that.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct NextSolutionRangeDescriptor {
    /// Solution range used for challenges.
    pub solution_range: u64,
}

/// Salt, if changed. This is broadcast in the each block of the eon, but only applies to the block
/// after that.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct NextSaltDescriptor {
    /// Salt used with challenges.
    pub salt: u64,
}

/// A digest item which is usable with Subspace consensus.
pub trait CompatibleDigestItem: Sized {
    /// Construct a digest item which contains a Subspace pre-digest.
    fn subspace_pre_digest(seal: PreDigest) -> Self;

    /// If this item is an Subspace pre-digest, return it.
    fn as_subspace_pre_digest(&self) -> Option<PreDigest>;

    /// Construct a digest item which contains a Subspace seal.
    fn subspace_seal(signature: FarmerSignature) -> Self;

    /// If this item is a Subspace signature, return the signature.
    fn as_subspace_seal(&self) -> Option<FarmerSignature>;

    /// If this item is a Subspace epoch descriptor, return it.
    fn as_next_epoch_descriptor(&self) -> Option<NextEpochDescriptor>;

    /// If this item is a Subspace config descriptor, return it.
    fn as_next_config_descriptor(&self) -> Option<NextConfigDescriptor>;
}

impl<Hash> CompatibleDigestItem for DigestItem<Hash>
where
    Hash: Send + Sync + Eq + Clone + Codec + 'static,
{
    fn subspace_pre_digest(digest: PreDigest) -> Self {
        DigestItem::PreRuntime(SUBSPACE_ENGINE_ID, digest.encode())
    }

    fn as_subspace_pre_digest(&self) -> Option<PreDigest> {
        self.pre_runtime_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn subspace_seal(signature: FarmerSignature) -> Self {
        DigestItem::Seal(SUBSPACE_ENGINE_ID, signature.encode())
    }

    fn as_subspace_seal(&self) -> Option<FarmerSignature> {
        self.seal_try_to(&SUBSPACE_ENGINE_ID)
    }

    fn as_next_epoch_descriptor(&self) -> Option<NextEpochDescriptor> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID)
            .and_then(|x: super::ConsensusLog| match x {
                super::ConsensusLog::NextEpochData(n) => Some(n),
                _ => None,
            })
    }

    fn as_next_config_descriptor(&self) -> Option<NextConfigDescriptor> {
        self.consensus_try_to(&SUBSPACE_ENGINE_ID)
            .and_then(|x: super::ConsensusLog| match x {
                super::ConsensusLog::NextConfigData(n) => Some(n),
                _ => None,
            })
    }
}