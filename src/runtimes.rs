// Copyright 2019 Parity Technologies (UK) Ltd.
// This file is part of substrate-subxt.
//
// subxt is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// subxt is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with substrate-subxt.  If not, see <http://www.gnu.org/licenses/>.

use sp_runtime::{
    generic::Header,
    traits::{
        BlakeTwo256,
        IdentifyAccount,
        Verify,
    },
    MultiSignature,
    OpaqueExtrinsic,
};

use subxt::{
    extrinsic::DefaultExtra,
    balances::{
        AccountData,
        Balances,
        BalancesEventTypeRegistry,
    },
    system::{
        System,
        SystemEventTypeRegistry,
    },
    EventTypeRegistry,
    Runtime,
    register_default_type_sizes
};

use self::phala::PhalaEventTypeRegistry;

/// PhalaNode concrete type definitions compatible with those for kusama, v0.7
///
/// # Note
///
/// Main difference is `type Address = AccountId`.
/// Also the contracts module is not part of the kusama runtime.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PhalaNodeRuntime;

impl Runtime for PhalaNodeRuntime {
    type Signature = MultiSignature;
    type Extra = DefaultExtra<Self>;

    fn register_type_sizes(event_type_registry: &mut EventTypeRegistry<Self>) {
        event_type_registry.with_system();

        event_type_registry.with_phala();
        event_type_registry.with_balances();
        register_default_type_sizes(event_type_registry);
    }
}

impl System for PhalaNodeRuntime {
    type Index = u32;
    type BlockNumber = u32;
    type Hash = sp_core::H256;
    type Hashing = BlakeTwo256;
    type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
    type Address = sp_runtime::MultiAddress<Self::AccountId, u32>;
    type Header = Header<Self::BlockNumber, BlakeTwo256>;
    type Extrinsic = OpaqueExtrinsic;
    type AccountData = AccountData<<Self as Balances>::Balance>;
}

impl Balances for PhalaNodeRuntime {
    type Balance = u128;
}

impl phala::Phala for PhalaNodeRuntime {}
pub mod phala {
    use codec::{Encode, Decode};
    use subxt::{
        module, Call,
        system::System,
        balances::Balances
    };
    use core::marker::PhantomData;

    #[derive(Encode, Decode, Debug, Default, Clone, PartialEq, Eq)]
    pub struct EthereumTxHash([u8; 32]);
    #[derive(Encode, Decode, Debug, Default, Clone, PartialEq, Eq)]
    pub struct EthereumAddress([u8; 20]);


    #[module]
    pub trait Phala: System + Balances {

    }

    #[derive(Clone, Debug, PartialEq, Call, Encode)]
    pub struct PushCommandCall<T: Phala> {
        pub _runtime: PhantomData<T>,
        pub contract_id: u32,
        pub payload: Vec<u8>,
    }
}
