//! INIT chunks exchanged out of band, so an association can start established.
//!
//! SNAP ([draft-hancke-tsvwg-snap]) lets two peers that already share a signalling channel
//! swap their INIT chunks there and skip the four-message SCTP handshake. The INIT therefore
//! has to exist before any [`Endpoint`](crate::Endpoint) or
//! [`Association`](crate::Association) does: [`LocalInit`] is that value for this peer and
//! [`RemoteInit`] the validated one received from the other.
//! [`Endpoint::connect_established`](crate::Endpoint::connect_established) takes one of each.
//!
//! [draft-hancke-tsvwg-snap]: https://datatracker.ietf.org/doc/draft-hancke-tsvwg-snap/

#[cfg(test)]
mod snap_test;

use bytes::Bytes;
use rand::random;
use shared::error::{Error, Result};

use crate::chunk::Chunk;
use crate::chunk::chunk_header::{CHUNK_HEADER_SIZE, ChunkHeader};
use crate::chunk::chunk_init::ChunkInit;
use crate::config::TransportConfig;
use crate::shared::AssociationId;
use crate::util::{AssociationIdGenerator, RandomAssociationIdGenerator, get_padding_size};

/// An INIT this peer advertised out of band.
///
/// It fixes the verification tag, initial TSN, receive window and stream counts the peer
/// will hold this endpoint to, so the association started from it takes those values from
/// here rather than from the configuration in force when it starts.
///
/// Not `Clone`, and consumed by the association it starts: two associations sharing a
/// verification tag could not be told apart on the wire.
///
/// ```compile_fail,E0382
/// use rtc_sctp::{ClientConfig, Endpoint, LocalInit, RemoteInit};
/// use std::net::SocketAddr;
///
/// fn start_two(endpoint: &mut Endpoint, remote: SocketAddr, local: LocalInit, peer: &RemoteInit) {
///     let _ = endpoint.connect_established(ClientConfig::default(), remote, local, peer);
///     let _ = endpoint.connect_established(ClientConfig::default(), remote, local, peer);
/// }
/// ```
#[derive(Debug)]
pub struct LocalInit {
    chunk: ChunkInit,
}

impl LocalInit {
    /// Generates the INIT to advertise.
    ///
    /// Creates no association, starts no timer and changes no endpoint state. The
    /// verification tag is random: no [`Endpoint`](crate::Endpoint) exists yet, so the
    /// generator configured with
    /// [`EndpointConfig::aid_generator`](crate::EndpointConfig::aid_generator) is not
    /// consulted.
    pub fn generate(config: &TransportConfig) -> Self {
        let initiate_tag = RandomAssociationIdGenerator::new().generate_aid();
        // Never zero, as for an association that sends its INIT: the cumulative ack point
        // starts one below the initial TSN.
        let initial_tsn = random::<u32>().max(1);

        let mut chunk = ChunkInit {
            initiate_tag,
            initial_tsn,
            advertised_receiver_window_credit: config.max_receive_buffer_size(),
            num_outbound_streams: config.max_num_outbound_streams(),
            num_inbound_streams: config.max_num_inbound_streams(),
            ..Default::default()
        };
        chunk.set_supported_extensions();

        Self { chunk }
    }

    /// The INIT chunk as it would appear on the wire, without trailing padding.
    pub fn chunk_bytes(&self) -> Bytes {
        self.chunk
            .marshal()
            .expect("an INIT built by `generate` holds only parameters that marshal")
    }

    pub(crate) fn initiate_tag(&self) -> AssociationId {
        self.chunk.initiate_tag
    }

    pub(crate) fn into_chunk(self) -> ChunkInit {
        self.chunk
    }
}

/// A peer's INIT, received out of band, that passed validation.
///
/// A distinct type from [`LocalInit`] so the two cannot be swapped. Two are equal when they
/// are the same chunk, whatever padding each arrived with, which is how a peer that repeats
/// its INIT is told from one that changes it.
#[derive(Debug, Clone)]
pub struct RemoteInit {
    chunk: ChunkInit,
    /// The chunk as received, without its padding.
    bytes: Bytes,
}

impl RemoteInit {
    /// Parses and validates one INIT chunk, with or without its trailing padding.
    ///
    /// # Errors
    ///
    /// A chunk that is truncated, is not an INIT, carries a zero initiate tag, offers zero
    /// streams in either direction or advertises a receive window under 1500 bytes is
    /// rejected with the error the on-wire INIT path reports for it. Anything after the
    /// chunk other than its padding is [`Error::ErrInitChunkTrailingData`].
    pub fn parse(chunk: &[u8]) -> Result<Self> {
        let raw = Bytes::copy_from_slice(chunk);
        let length = CHUNK_HEADER_SIZE + ChunkHeader::unmarshal(&raw)?.value_length();
        // On the wire the next chunk may follow, so the chunk parsers accept that. Here
        // there is exactly one.
        if raw.len() > length + get_padding_size(length) {
            return Err(Error::ErrInitChunkTrailingData);
        }

        let chunk = ChunkInit::unmarshal(&raw)?;
        // `ChunkInit` decodes INIT ACK too, and an INIT ACK is not a valid advertisement.
        if chunk.is_ack {
            return Err(Error::ErrChunkTypeNotTypeInit);
        }
        chunk.check()?;

        Ok(Self {
            chunk,
            bytes: raw.slice(..length),
        })
    }

    pub(crate) fn initiate_tag(&self) -> AssociationId {
        self.chunk.initiate_tag
    }

    pub(crate) fn chunk(&self) -> &ChunkInit {
        &self.chunk
    }
}

impl PartialEq for RemoteInit {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for RemoteInit {}
