use super::*;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_type::{
    CT_COOKIE_ACK, CT_COOKIE_ECHO, CT_INIT, CT_INIT_ACK, CT_PAYLOAD_DATA, ChunkType,
};
use crate::packet::Packet;
use crate::{
    Association, AssociationHandle, ClientConfig, ConnectError, DatagramEvent, Endpoint,
    EndpointConfig, Event, Payload, PayloadProtocolIdentifier,
};
use assert_matches::assert_matches;
use shared::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// The example INIT chunks of draft-hancke-tsvwg-snap-01 section 7. Each is 30 bytes, so
/// its padded form is two bytes longer.
const DRAFT_OFFER_INIT: [u8; 30] = [
    0x01, 0x00, 0x00, 0x1e, 0x8a, 0x2c, 0xdd, 0x1d, 0x00, 0x50, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xe0, 0x79, 0x65, 0x1d, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x06, 0x82, 0xc0,
];
const DRAFT_ANSWER_INIT: [u8; 30] = [
    0x01, 0x00, 0x00, 0x1e, 0x5f, 0xb3, 0x74, 0x74, 0x00, 0x50, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xa1, 0xaa, 0xdc, 0x74, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x06, 0x82, 0xc0,
];

const HANDSHAKE_CHUNKS: [ChunkType; 4] = [CT_INIT, CT_INIT_ACK, CT_COOKIE_ECHO, CT_COOKIE_ACK];

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// An endpoint with no server configuration, so it cannot answer an INIT sent on the wire.
fn endpoint(local: SocketAddr) -> Endpoint {
    Endpoint::new(
        local,
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::new()),
        None,
    )
}

/// One endpoint with one association, joined to its peer by `deliver`.
struct Peer {
    addr: SocketAddr,
    endpoint: Endpoint,
    handle: AssociationHandle,
    association: Association,
}

impl Peer {
    fn start(
        addr: SocketAddr,
        remote: SocketAddr,
        config: TransportConfig,
        local: LocalInit,
        peer: &RemoteInit,
    ) -> Self {
        let mut endpoint = endpoint(addr);
        let (handle, association) = endpoint
            .connect_established(ClientConfig::new(config), remote, local, peer)
            .expect("the endpoint is empty, so the advertised tag is free");
        Self {
            addr,
            endpoint,
            handle,
            association,
        }
    }

    /// Hands everything this peer has to send to `to`, returning the packets sent.
    fn deliver(&mut self, now: Instant, to: &mut Peer) -> Vec<Packet> {
        let mut sent = vec![];
        while let Some(transmit) = self.association.poll_transmit(now) {
            let Payload::RawEncode(datagrams) = transmit.message else {
                panic!("an association only transmits encoded packets");
            };
            for datagram in datagrams {
                sent.push(Packet::unmarshal(&datagram).expect("outbound packets are well formed"));

                let (handle, event) = to
                    .endpoint
                    .handle(now, self.addr, None, datagram)
                    .expect("the packet carries the tag the receiver advertised");
                assert_eq!(handle, to.handle);
                let DatagramEvent::AssociationEvent(event) = event else {
                    panic!("the packet must reach the existing association, not create one");
                };
                to.association.handle_event(event);
            }
        }
        sent
    }

    fn send(&mut self, now: Instant, stream: u16, message: &'static [u8]) {
        self.association
            .open_stream(stream, PayloadProtocolIdentifier::Binary)
            .unwrap()
            .write_sctp(
                now,
                &Bytes::from_static(message),
                PayloadProtocolIdentifier::Binary,
            )
            .unwrap();
    }
}

/// Two peers started from each other's INIT, `a` advertising what `a_advertised` describes.
fn established_pair(a_advertised: &TransportConfig) -> (Peer, Peer) {
    let a_init = LocalInit::generate(a_advertised);
    let b_init = LocalInit::generate(&TransportConfig::default());
    let a_sees = RemoteInit::parse(&b_init.chunk_bytes()).unwrap();
    let b_sees = RemoteInit::parse(&a_init.chunk_bytes()).unwrap();

    (
        Peer::start(
            addr(5001),
            addr(5002),
            TransportConfig::default(),
            a_init,
            &a_sees,
        ),
        Peer::start(
            addr(5002),
            addr(5001),
            TransportConfig::default(),
            b_init,
            &b_sees,
        ),
    )
}

fn chunk_types(packets: &[Packet]) -> Vec<ChunkType> {
    packets
        .iter()
        .flat_map(|packet| packet.chunks.iter().map(|chunk| chunk.header().typ))
        .collect()
}

#[test]
fn associations_started_from_each_others_init_exchange_data_without_a_handshake() {
    let now = Instant::now();
    let (mut a, mut b) = established_pair(&TransportConfig::default());

    assert_matches!(a.association.poll(), Some(Event::Connected));
    assert_matches!(b.association.poll(), Some(Event::Connected));

    a.send(now, 1, b"ping");
    let mut sent = a.deliver(now, &mut b);

    let mut stream = b
        .association
        .accept_stream()
        .expect("the DATA opens stream 1");
    let mut buf = [0u8; 16];
    let n = stream.read_sctp().unwrap().unwrap().read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");

    // The reply travels under the tag `a` advertised, so it proves `a` routes by that tag.
    stream
        .write_sctp(
            now,
            &Bytes::from_static(b"pong"),
            PayloadProtocolIdentifier::Binary,
        )
        .unwrap();
    sent.extend(b.deliver(now, &mut a));

    let n = a
        .association
        .stream(1)
        .unwrap()
        .read_sctp()
        .unwrap()
        .unwrap()
        .read(&mut buf)
        .unwrap();
    assert_eq!(&buf[..n], b"pong");

    let sent = chunk_types(&sent);
    assert_eq!(
        sent.iter().filter(|typ| **typ == CT_PAYLOAD_DATA).count(),
        2
    );
    assert!(
        !sent.iter().any(|typ| HANDSHAKE_CHUNKS.contains(typ)),
        "handshake chunk on the wire: {sent:?}"
    );
}

#[test]
fn association_keeps_what_its_init_advertised_over_the_config_it_starts_with() {
    let now = Instant::now();
    let advertised = TransportConfig::default()
        .with_max_receive_buffer_size(64 * 1024)
        .with_max_num_inbound_streams(16)
        .with_max_num_outbound_streams(16);
    // `a` starts with the default configuration, which is larger on every count.
    let (mut a, mut b) = established_pair(&advertised);

    assert_eq!(a.association.negotiated_max_streams(), Some(16));

    b.send(now, 1, b"ping");
    b.deliver(now, &mut a);
    let ack_due = a.association.poll_timeout().expect("the delayed ack");
    a.association.handle_timeout(ack_due);
    let acks = a.deliver(ack_due, &mut b);
    let window = acks
        .iter()
        .flat_map(|packet| &packet.chunks)
        .find_map(|chunk| chunk.as_any().downcast_ref::<ChunkSelectiveAck>())
        .expect("the DATA is acknowledged")
        .advertised_receiver_window_credit;
    assert!(window <= 64 * 1024, "acknowledged a {window} byte window");
}

#[test]
fn packets_carry_the_configured_ports() {
    let now = Instant::now();
    let local = LocalInit::generate(&TransportConfig::default());
    let peer = RemoteInit::parse(&DRAFT_OFFER_INIT).unwrap();
    let mut a = Peer::start(
        addr(5001),
        addr(5002),
        TransportConfig::default()
            .with_sctp_port(6000)
            .with_remote_sctp_port(7000),
        local,
        &peer,
    );

    a.send(now, 1, b"ping");
    let transmit = a.association.poll_transmit(now).expect("the DATA");
    let Payload::RawEncode(datagrams) = transmit.message else {
        panic!("an association only transmits encoded packets");
    };
    let header = Packet::unmarshal(&datagrams[0]).unwrap().common_header;
    assert_eq!((header.source_port, header.destination_port), (6000, 7000));
}

#[test]
fn the_same_chunk_is_equal_with_or_without_its_padding() {
    let unpadded = RemoteInit::parse(&DRAFT_OFFER_INIT).unwrap();
    let mut padded = DRAFT_OFFER_INIT.to_vec();
    padded.extend([0, 0]);

    assert_eq!(unpadded, RemoteInit::parse(&padded).unwrap());
    assert_ne!(unpadded, RemoteInit::parse(&DRAFT_ANSWER_INIT).unwrap());
}

#[test]
fn invalid_init_is_rejected() {
    assert_matches!(
        RemoteInit::parse(&DRAFT_OFFER_INIT[..DRAFT_OFFER_INIT.len() - 1]),
        Err(Error::ErrChunkHeaderNotEnoughSpace)
    );

    let mut init_ack = DRAFT_OFFER_INIT;
    init_ack[0] = CT_INIT_ACK.0;
    assert_matches!(
        RemoteInit::parse(&init_ack),
        Err(Error::ErrChunkTypeNotTypeInit)
    );

    // Two padding bytes complete the chunk. The chunk parsers would take what follows for
    // the next chunk.
    let mut followed = DRAFT_OFFER_INIT.to_vec();
    followed.extend([0, 0, 0, 0, 0, 0]);
    assert_matches!(
        RemoteInit::parse(&followed),
        Err(Error::ErrInitChunkTrailingData)
    );

    let mut zero_tag = DRAFT_OFFER_INIT;
    zero_tag[4..8].fill(0);
    assert_matches!(
        RemoteInit::parse(&zero_tag),
        Err(Error::ErrChunkTypeInitInitiateTagZero)
    );
}

#[test]
fn an_initiate_tag_that_already_routes_to_an_association_is_refused() {
    let peer = RemoteInit::parse(&DRAFT_OFFER_INIT).unwrap();
    let first = LocalInit::generate(&TransportConfig::default());
    let same_tag = LocalInit {
        chunk: ChunkInit::unmarshal(&first.chunk_bytes()).unwrap(),
    };

    let mut endpoint = endpoint(addr(5001));
    endpoint
        .connect_established(ClientConfig::default(), addr(5002), first, &peer)
        .unwrap();
    let refused = endpoint
        .connect_established(ClientConfig::default(), addr(5002), same_tag, &peer)
        .err();
    assert_eq!(refused, Some(ConnectError::InitiateTagInUse));
}
