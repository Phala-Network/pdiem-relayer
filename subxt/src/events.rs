// Copyright 2019-2020 Parity Technologies (UK) Ltd.
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

use codec::{
    Codec,
    Compact,
    Decode,
    Encode,
    Input,
    Output,
};
use frame_support::dispatch::DispatchInfo;
use sp_runtime::{
    DispatchError,
    DispatchResult,
};
use std::{
    collections::{
        HashMap,
        HashSet,
    },
    fmt,
    marker::{
        PhantomData,
        Send,
    },
};

use crate::{
    error::{
        Error,
        RuntimeError,
    },
    metadata::{
        EventArg,
        Metadata,
    },
    Phase,
    System,
};

/// Raw bytes for an Event
pub struct RawEvent {
    /// The name of the module from whence the Event originated
    pub module: String,
    /// The name of the Event
    pub variant: String,
    /// The raw Event data
    pub data: Vec<u8>,
}

impl std::fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RawEvent")
            .field("module", &self.module)
            .field("variant", &self.variant)
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}

trait TypeSegmenter: Send {
    /// Consumes an object from an input stream, and output the serialized bytes.
    fn segment(&self, input: &mut &[u8], output: &mut Vec<u8>) -> Result<(), Error>;
}

#[derive(Default)]
struct TypeMarker<T>(PhantomData<T>);
impl<T> TypeSegmenter for TypeMarker<T>
where
    T: Codec + Send,
{
    fn segment(&self, input: &mut &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
        T::decode(input).map_err(Error::from)?.encode_to(output);
        Ok(())
    }
}

/// Events decoder.
pub struct EventsDecoder<T> {
    metadata: Metadata,
    type_segmenters: HashMap<String, Box<dyn TypeSegmenter>>,
    marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for EventsDecoder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventsDecoder<T>")
            .field("metadata", &self.metadata)
            .field(
                "type_segmenters",
                &self.type_segmenters.keys().cloned().collect::<String>(),
            )
            .finish()
    }
}

impl<T: System> EventsDecoder<T> {
    /// Creates a new `EventsDecoder`.
    pub fn new(metadata: Metadata) -> Self {
        let mut decoder = Self {
            metadata,
            type_segmenters: HashMap::new(),
            marker: PhantomData,
        };
        // register default event arg type sizes for dynamic decoding of events
        decoder.register_type_size::<()>("PhantomData");
        decoder.register_type_size::<DispatchInfo>("DispatchInfo");
        decoder.register_type_size::<bool>("bool");
        decoder.register_type_size::<u32>("ReferendumIndex");
        decoder.register_type_size::<[u8; 16]>("Kind");
        decoder.register_type_size::<[u8; 32]>("AuthorityId");
        decoder.register_type_size::<u8>("u8");
        decoder.register_type_size::<u32>("u32");
        decoder.register_type_size::<u64>("u64");
        decoder.register_type_size::<u128>("u128");
        decoder.register_type_size::<u32>("AccountIndex");
        decoder.register_type_size::<u32>("SessionIndex");
        decoder.register_type_size::<u32>("PropIndex");
        decoder.register_type_size::<u32>("ProposalIndex");
        decoder.register_type_size::<u32>("AuthorityIndex");
        decoder.register_type_size::<u64>("AuthorityWeight");
        decoder.register_type_size::<u32>("MemberCount");
        decoder.register_type_size::<T::AccountId>("AccountId");
        decoder.register_type_size::<T::BlockNumber>("BlockNumber");
        decoder.register_type_size::<T::Hash>("Hash");
        decoder.register_type_size::<u8>("VoteThreshold");
        // Additional types
        decoder.register_type_size::<(T::BlockNumber, u32)>("TaskAddress<BlockNumber>");
        decoder
    }

    /// Register a type.
    pub fn register_type_size<U>(&mut self, name: &str) -> usize
        where
            U: Default + Codec + Send + 'static,
    {
        let size = U::default().encode().len();
        // A segmenter decodes a type from an input stream (&mut &[u8]) and returns the serialized
        // type to the output stream (&mut Vec<u8>).
        self.type_segmenters
            .insert(name.to_string(), Box::new(TypeMarker::<U>::default()));
        size
    }

    /// Check missing type sizes.
    pub fn check_missing_type_sizes(&self) {
        let mut missing = HashSet::new();
        for module in self.metadata.modules_with_events() {
            for event in module.events() {
                for arg in event.arguments() {
                    for primitive in arg.primitives() {
                        if !self.type_segmenters.contains_key(&primitive) {
                            missing.insert(format!(
                                "{}::{}::{}",
                                module.name(),
                                event.name,
                                primitive
                            ));
                        }
                    }
                }
            }
        }
        if !missing.is_empty() {
            log::warn!(
                "The following primitive types do not have registered sizes: {:?} \
                If any of these events are received, an error will occur since we cannot decode them",
                missing
            );
        }
    }

    fn decode_raw_bytes<W: Output>(
        &self,
        args: &[EventArg],
        input: &mut &[u8],
        output: &mut W,
        errors: &mut Vec<RuntimeError>,
    ) -> Result<(), Error> {
        for arg in args {
            match arg {
                EventArg::Vec(arg) => {
                    let len = <Compact<u32>>::decode(input)?;
                    len.encode_to(output);
                    for _ in 0..len.0 {
                        self.decode_raw_bytes(&[*arg.clone()], input, output, errors)?
                    }
                }
                EventArg::Option(arg) => {
                    match input.read_byte()? {
                        0 => output.push_byte(0),
                        1 => {
                            output.push_byte(1);
                            self.decode_raw_bytes(&[*arg.clone()], input, output, errors)?
                        }
                        _ => {
                            return Err(Error::Other(
                                "unexpected first byte decoding Option".into(),
                            ))
                        }
                    }
                }
                EventArg::Tuple(args) => {
                    self.decode_raw_bytes(args, input, output, errors)?
                }
                EventArg::Primitive(name) => {
                    let result = match name.as_str() {
                        "DispatchResult" => DispatchResult::decode(input)?,
                        "DispatchError" => Err(DispatchError::decode(input)?),
                        _ => {
                            if let Some(seg) = self.type_segmenters.get(name) {
                                let mut buf = Vec::<u8>::new();
                                seg.segment(input, &mut buf)?;
                                output.write(&buf);
                                Ok(())
                            } else {
                                return Err(Error::TypeSizeUnavailable(name.to_owned()))
                            }
                        }
                    };
                    if let Err(error) = result {
                        // since the input may contain any number of args we propagate
                        // runtime errors to the caller for handling
                        errors.push(RuntimeError::from_dispatch(&self.metadata, error)?);
                    }
                }
            }
        }
        Ok(())
    }

    /// Decode events.
    pub fn decode_events(&self, input: &mut &[u8]) -> Result<Vec<(Phase, Raw)>, Error> {
        let compact_len = <Compact<u32>>::decode(input)?;
        let len = compact_len.0 as usize;

        let mut r = Vec::new();
        for _ in 0..len {
            // decode EventRecord
            let phase = Phase::decode(input)?;
            let module_variant = input.read_byte()?;

            let module = self.metadata.module_with_events(module_variant)?;
            let event_variant = input.read_byte()?;
            let event_metadata = module.event(event_variant)?;

            log::debug!(
                "received event '{}::{}' ({:?})",
                module.name(),
                event_metadata.name,
                event_metadata.arguments()
            );

            let mut event_data = Vec::<u8>::new();
            let mut event_errors = Vec::<RuntimeError>::new();
            let result = self.decode_raw_bytes(
                &event_metadata.arguments(),
                input,
                &mut event_data,
                &mut event_errors,
            );
            let raw = match result {
                Ok(()) => {
                    log::debug!("raw bytes: {}", hex::encode(&event_data),);

                    let event = RawEvent {
                        module: module.name().to_string(),
                        variant: event_metadata.name.clone(),
                        data: event_data,
                    };

                    // topics come after the event data in EventRecord
                    let _topics = Vec::<T::Hash>::decode(input)?;
                    Raw::Event(event)
                }
                Err(err) => return Err(err),
            };

            if event_errors.len() == 0 {
                r.push((phase.clone(), raw));
            }

            for err in event_errors {
                r.push((phase.clone(), Raw::Error(err)));
            }
        }
        Ok(r)
    }
}

/// Raw event or error event
#[derive(Debug)]
pub enum Raw {
    /// Event
    Event(RawEvent),
    /// Error
    Error(RuntimeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_metadata::{
        DecodeDifferent,
        ErrorMetadata,
        EventMetadata,
        ExtrinsicMetadata,
        ModuleMetadata,
        RuntimeMetadata,
        RuntimeMetadataPrefixed,
        RuntimeMetadataV12,
        META_RESERVED,
    };
    use std::convert::TryFrom;

    type TestRuntime = crate::NodeTemplateRuntime;

    #[test]
    fn test_decode_option() {
        let decoder = EventsDecoder::<TestRuntime>::new(Metadata::default());

        let value = Some(0u8);
        let input = value.encode();
        let mut output = Vec::<u8>::new();
        let mut errors = Vec::<RuntimeError>::new();

        decoder
            .decode_raw_bytes(
                &[EventArg::Option(Box::new(EventArg::Primitive(
                    "u8".to_string(),
                )))],
                &mut &input[..],
                &mut output,
                &mut errors,
            )
            .unwrap();

        assert_eq!(output, vec![1, 0]);
    }

    #[test]
    fn test_decode_system_events_and_error() {
        let decoder = EventsDecoder::<TestRuntime>::new(
            Metadata::try_from(RuntimeMetadataPrefixed(
                META_RESERVED,
                RuntimeMetadata::V12(RuntimeMetadataV12 {
                    modules: DecodeDifferent::Decoded(vec![ModuleMetadata {
                        name: DecodeDifferent::Decoded("System".to_string()),
                        storage: None,
                        calls: None,
                        event: Some(DecodeDifferent::Decoded(vec![
                            EventMetadata {
                                name: DecodeDifferent::Decoded(
                                    "ExtrinsicSuccess".to_string(),
                                ),
                                arguments: DecodeDifferent::Decoded(vec![
                                    "DispatchInfo".to_string()
                                ]),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                            EventMetadata {
                                name: DecodeDifferent::Decoded(
                                    "ExtrinsicFailed".to_string(),
                                ),
                                arguments: DecodeDifferent::Decoded(vec![
                                    "DispatchError".to_string(),
                                    "DispatchInfo".to_string(),
                                ]),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                        ])),
                        constants: DecodeDifferent::Decoded(vec![]),
                        errors: DecodeDifferent::Decoded(vec![
                            ErrorMetadata {
                                name: DecodeDifferent::Decoded(
                                    "InvalidSpecName".to_string(),
                                ),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                            ErrorMetadata {
                                name: DecodeDifferent::Decoded(
                                    "SpecVersionNeedsToIncrease".to_string(),
                                ),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                            ErrorMetadata {
                                name: DecodeDifferent::Decoded(
                                    "FailedToExtractRuntimeVersion".to_string(),
                                ),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                            ErrorMetadata {
                                name: DecodeDifferent::Decoded(
                                    "NonDefaultComposite".to_string(),
                                ),
                                documentation: DecodeDifferent::Decoded(vec![]),
                            },
                        ]),
                        index: 0,
                    }]),
                    extrinsic: ExtrinsicMetadata {
                        version: 0,
                        signed_extensions: vec![],
                    },
                }),
            ))
            .unwrap(),
        );

        // [(ApplyExtrinsic(0), Event(RawEvent { module: "System", variant: "ExtrinsicSuccess", data: "482d7c09000000000200" })), (ApplyExtrinsic(1), Error(Module(ModuleError { module: "System", error: "NonDefaultComposite" }))), (ApplyExtrinsic(2), Error(Module(ModuleError { module: "System", error: "NonDefaultComposite" })))]
        let input = hex::decode("0c00000000000000482d7c0900000000020000000100000000010300035884723300000000000000000200000000010300035884723300000000000000").unwrap();
        decoder.decode_events(&mut &input[..]).unwrap();
    }
}
