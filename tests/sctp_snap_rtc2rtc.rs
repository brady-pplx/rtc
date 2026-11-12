//! SNAP: two peers that exchange their SCTP INIT chunks in SDP start the association without
//! the SCTP handshake, and a peer that meets one without SNAP falls back to it.
//!
//! The peers exchange datagrams in memory, on a virtual clock. The offerer sends on its
//! negotiated channel the moment it opens and the answerer replies to what it receives, so the
//! first SCTP packet a handshake-free association carries is the offerer's message.
//!
//! SCTP runs inside DTLS, so its chunks cannot be read off the wire. What can be read without
//! decrypting is the record header: every SCTP packet is one DTLS application-data record. A
//! handshake has each peer send two of them (INIT and COOKIE ECHO, or INIT ACK and COOKIE ACK)
//! before any message can arrive; without one, the answerer has sent none when the message
//! arrives in the first it reads.

use anyhow::Result;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::{SctpSnapMode, SettingEngineBuilder};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCSctpSnapOutcome,
    RTCSctpSnapUnusedReason,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The stream id both peers agree on out-of-band.
const NEGOTIATED_ID: u16 = 0;

/// How far the virtual clock may run before the test gives up.
const DEADLINE: Duration = Duration::from_secs(30);

/// A bound on the turns, should a timer keep firing without the clock moving.
const MAX_TURNS: usize = 10_000;

const SCTP_INIT_ATTRIBUTE: &str = "a=sctp-init:";

/// The example values of draft-hancke-tsvwg-snap-01 section 7: two valid INIT chunks.
const DRAFT_OFFER_SCTP_INIT: &str = "AQAAHols3R0AUAAA/////+B5ZR3AAAAEgAgABoLA";
const DRAFT_ANSWER_SCTP_INIT: &str = "AQAAHl+zdHQAUAAA/////6Gq3HTAAAAEgAgABoLA";

/// DTLS application-data records a peer has read and written (RFC 6347 section 4.1: the
/// record's first byte is its content type, 23 for application data).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SctpPackets {
    read: usize,
    written: usize,
}

fn is_application_data_record(datagram: &[u8]) -> bool {
    datagram.first() == Some(&23)
}

struct Peer {
    name: &'static str,
    pc: RTCPeerConnection,
    addr: SocketAddr,
    channel: RTCDataChannelId,
    /// Datagrams that reached this peer and that it has not read yet.
    inbox: Vec<TaggedBytesMut>,
    /// What this peer sends the moment its channel opens, if anything.
    greeting: Option<&'static str>,
    /// What this peer answers each message it receives with, if anything.
    reply: Option<&'static str>,
    opened: bool,
    received: Vec<String>,
    sctp_packets: SctpPackets,
    /// `sctp_packets` as it stood when the first message was received.
    sctp_packets_at_first_message: Option<SctpPackets>,
}

impl Peer {
    fn new(
        name: &'static str,
        addr: SocketAddr,
        snap: SctpSnapMode,
        answering_dtls_role: RTCDtlsRole,
        now: Instant,
    ) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(answering_dtls_role)
                    .with_sctp_snap(snap)
                    .build(),
            )
            .build(now)?;
        let host = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        pc.add_local_candidate(RTCIceCandidate::from(&host).to_json()?)?;
        let channel = pc
            .create_data_channel(
                "negotiated",
                Some(RTCDataChannelInit {
                    negotiated: Some(NEGOTIATED_ID),
                    ..Default::default()
                }),
            )?
            .id();
        Ok(Self {
            name,
            pc,
            addr,
            channel,
            inbox: Vec::new(),
            greeting: None,
            reply: None,
            opened: false,
            received: Vec::new(),
            sctp_packets: SctpPackets::default(),
            sctp_packets_at_first_message: None,
        })
    }

    /// One turn: everything that reached this peer, then its events, then its reads. Returns
    /// the datagrams it wrote.
    fn turn(&mut self, now: Instant) -> Result<Vec<TaggedBytesMut>> {
        for datagram in self.inbox.drain(..) {
            if is_application_data_record(&datagram.message) {
                self.sctp_packets.read += 1;
            }
            self.pc.handle_read(datagram)?;
        }
        while let Some(event) = self.pc.poll_event() {
            if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
                assert_eq!(
                    id, self.channel,
                    "{}: an unexpected channel opened",
                    self.name
                );
                self.opened = true;
                if let Some(greeting) = self.greeting {
                    self.send(now, greeting)?;
                }
            }
        }
        while let Some(read) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(id, message) = read.message {
                assert_eq!(
                    id, self.channel,
                    "{}: a message on another channel",
                    self.name
                );
                self.received
                    .push(String::from_utf8_lossy(&message.data).into_owned());
                self.sctp_packets_at_first_message
                    .get_or_insert(self.sctp_packets);
                if let Some(reply) = self.reply {
                    self.send(now, reply)?;
                }
            }
        }
        let mut written = Vec::new();
        while let Some(datagram) = self.pc.poll_write() {
            if is_application_data_record(&datagram.message) {
                self.sctp_packets.written += 1;
            }
            written.push(datagram);
        }
        Ok(written)
    }

    fn send(&mut self, now: Instant, text: &str) -> Result<()> {
        self.pc
            .data_channel(self.channel)
            .expect("an open channel exists")
            .send_text(now, text.to_owned())?;
        Ok(())
    }

    /// Hands this peer the datagrams `from` wrote to it, as its socket would.
    fn deliver(&mut self, from: SocketAddr, datagrams: Vec<TaggedBytesMut>, now: Instant) {
        for datagram in datagrams {
            assert_eq!(
                datagram.transport.peer_addr, self.addr,
                "{from} wrote to an address other than its peer's"
            );
            self.inbox.push(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: datagram.message,
            });
        }
    }

    fn snap_outcome(&self) -> RTCSctpSnapOutcome {
        self.pc
            .sctp()
            .expect("a negotiated data section starts the SCTP transport")
            .snap_outcome()
    }
}

/// An offerer that sends `ping` when its channel opens and an answerer that replies `pong`.
struct Call {
    start: Instant,
    offerer: Peer,
    answerer: Peer,
}

impl Call {
    fn new(
        offerer_snap: SctpSnapMode,
        answerer_snap: SctpSnapMode,
        answering_dtls_role: RTCDtlsRole,
    ) -> Result<Self> {
        let start = Instant::now();
        let mut offerer = Peer::new(
            "offerer",
            "127.0.0.1:50000".parse()?,
            offerer_snap,
            // Unused: only the answerer picks a role.
            RTCDtlsRole::Server,
            start,
        )?;
        offerer.greeting = Some("ping");
        let mut answerer = Peer::new(
            "answerer",
            "127.0.0.1:50001".parse()?,
            answerer_snap,
            answering_dtls_role,
            start,
        )?;
        answerer.reply = Some("pong");
        Ok(Self {
            start,
            offerer,
            answerer,
        })
    }

    /// A call whose messages have gone both ways.
    fn connected(offerer_snap: SctpSnapMode, answerer_snap: SctpSnapMode) -> Result<Self> {
        let mut call = Self::new(offerer_snap, answerer_snap, RTCDtlsRole::Client)?;
        call.negotiate()?;
        call.run()?;
        call.assert_messages_round_tripped("connected");
        Ok(call)
    }

    /// Runs offer/answer and returns both descriptions as they went over signalling.
    fn negotiate(&mut self) -> Result<(RTCSessionDescription, RTCSessionDescription)> {
        let now = self.start;
        let offer = self.offerer.pc.create_offer(None)?;
        self.offerer.pc.set_local_description(now, offer.clone())?;
        self.answerer
            .pc
            .set_remote_description(now, offer.clone())?;
        let answer = self.answerer.pc.create_answer(None)?;
        self.answerer
            .pc
            .set_local_description(now, answer.clone())?;
        self.offerer
            .pc
            .set_remote_description(now, answer.clone())?;
        Ok((offer, answer))
    }

    /// Exchanges datagrams until the offerer has its reply, or the deadline passes.
    fn run(&mut self) -> Result<()> {
        let (offerer, answerer) = (&mut self.offerer, &mut self.answerer);
        let mut now = self.start;
        let mut turns = 0;
        while offerer.received.is_empty()
            && now.duration_since(self.start) < DEADLINE
            && turns < MAX_TURNS
        {
            turns += 1;
            let written = offerer.turn(now)?;
            answerer.deliver(offerer.addr, written, now);
            let written = answerer.turn(now)?;
            offerer.deliver(answerer.addr, written, now);

            // Nothing in flight: move the clock to the next timer.
            if offerer.inbox.is_empty() && answerer.inbox.is_empty() {
                let next = [offerer.pc.poll_timeout(), answerer.pc.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                let Some(next) = next else { break };
                now = now.max(next);
                offerer.pc.handle_timeout(now)?;
                answerer.pc.handle_timeout(now)?;
            }
        }
        Ok(())
    }

    fn assert_messages_round_tripped(&self, case: &str) {
        assert!(
            self.offerer.opened && self.answerer.opened,
            "{case}: both channels should open (offerer={}, answerer={})",
            self.offerer.opened,
            self.answerer.opened
        );
        assert_eq!(self.answerer.received, ["ping"], "{case}: answerer");
        assert_eq!(self.offerer.received, ["pong"], "{case}: offerer");
    }
}

/// The `a=sctp-init` values a description carries.
fn sctp_inits(description: &RTCSessionDescription) -> Vec<&str> {
    description
        .sdp
        .lines()
        .filter_map(|line| line.strip_prefix(SCTP_INIT_ATTRIBUTE))
        .collect()
}

/// `description` with every `a=sctp-init` line replaced by one line per value in `values`.
/// A description that carries none gets them at the end, which is its data section when
/// that is the only section, as it is throughout this file.
fn with_sctp_inits(
    description: &RTCSessionDescription,
    values: &[&str],
) -> Result<RTCSessionDescription> {
    let mut lines: Vec<String> = description
        .sdp
        .lines()
        .filter(|line| !line.starts_with(SCTP_INIT_ATTRIBUTE))
        .map(str::to_owned)
        .collect();
    lines.extend(
        values
            .iter()
            .map(|value| format!("{SCTP_INIT_ATTRIBUTE}{value}")),
    );
    let sdp = lines.join("\r\n") + "\r\n";
    Ok(RTCSessionDescription::offer(sdp)?)
}

/// Both DTLS roles, because without a handshake neither is the SCTP client: the DTLS client
/// finishes last, and the offerer's message can reach it before it has seen its own handshake
/// complete.
#[test]
fn peers_that_both_offer_snap_exchange_messages_with_no_sctp_handshake() -> Result<()> {
    for answering_dtls_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let case = format!("answerer is DTLS {answering_dtls_role}");
        let mut call = Call::new(
            SctpSnapMode::Offer,
            SctpSnapMode::Offer,
            answering_dtls_role,
        )?;

        let (offer, answer) = call.negotiate()?;
        assert_eq!(sctp_inits(&offer).len(), 1, "{case}: offer");
        assert_eq!(sctp_inits(&answer).len(), 1, "{case}: answer");
        assert_eq!(
            call.offerer.snap_outcome(),
            RTCSctpSnapOutcome::Pending,
            "{case}: DTLS has not finished"
        );

        call.run()?;

        call.assert_messages_round_tripped(&case);
        assert_eq!(
            call.offerer.snap_outcome(),
            RTCSctpSnapOutcome::Used,
            "{case}"
        );
        assert_eq!(
            call.answerer.snap_outcome(),
            RTCSctpSnapOutcome::Used,
            "{case}"
        );
        assert_eq!(
            call.answerer.sctp_packets_at_first_message,
            Some(SctpPackets {
                read: 1,
                written: 0
            }),
            "{case}: the offerer's message must be the first SCTP packet either peer sends"
        );

        call.offerer.pc.close()?;
        call.answerer.pc.close()?;
    }
    Ok(())
}

/// Unless both peers advertise an INIT, none is used: the answer carries none, the SCTP
/// handshake runs, and each side reports why. The last row is the default configuration.
#[test]
fn a_peer_without_snap_gets_the_sctp_handshake() -> Result<()> {
    use RTCSctpSnapOutcome::NotUsed;
    use RTCSctpSnapUnusedReason::{Disabled, PeerDidNotOffer};
    use SctpSnapMode::Offer;

    for (offerer_snap, answerer_snap, offerer_outcome, answerer_outcome) in [
        (
            Offer,
            SctpSnapMode::Disabled,
            NotUsed(PeerDidNotOffer),
            NotUsed(Disabled),
        ),
        (
            SctpSnapMode::Disabled,
            Offer,
            NotUsed(Disabled),
            NotUsed(PeerDidNotOffer),
        ),
        (
            SctpSnapMode::Disabled,
            SctpSnapMode::Disabled,
            NotUsed(Disabled),
            NotUsed(Disabled),
        ),
    ] {
        for answering_dtls_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            let case = format!(
                "offerer {offerer_snap:?}, answerer {answerer_snap:?} and DTLS {answering_dtls_role}"
            );
            let mut call = Call::new(offerer_snap, answerer_snap, answering_dtls_role)?;

            let (offer, answer) = call.negotiate()?;
            assert_eq!(
                sctp_inits(&offer).len(),
                usize::from(offerer_snap == Offer),
                "{case}: offer"
            );
            assert!(sctp_inits(&answer).is_empty(), "{case}: answer");

            call.run()?;

            call.assert_messages_round_tripped(&case);
            assert_eq!(call.offerer.snap_outcome(), offerer_outcome, "{case}");
            assert_eq!(call.answerer.snap_outcome(), answerer_outcome, "{case}");
            let at_first_message = call
                .answerer
                .sctp_packets_at_first_message
                .expect("the answerer received a message");
            assert!(
                at_first_message.written >= 2,
                "{case}: the handshake has the answerer send two SCTP packets before a message \
                 can reach it, and it had sent {}",
                at_first_message.written
            );

            call.offerer.pc.close()?;
            call.answerer.pc.close()?;
        }
    }
    Ok(())
}

fn answerer(snap: SctpSnapMode) -> Result<Peer> {
    Peer::new(
        "answerer",
        "127.0.0.1:50001".parse()?,
        snap,
        RTCDtlsRole::Client,
        Instant::now(),
    )
}

/// The peer's attribute is untrusted input. A valid INIT is the control: it shows the
/// rewritten offers are refused for their INIT and nothing else.
#[test]
fn an_offer_is_refused_for_an_sctp_init_that_is_not_one_base64_init_chunk() -> Result<()> {
    let now = Instant::now();
    let offer = Call::new(
        SctpSnapMode::Offer,
        SctpSnapMode::Offer,
        RTCDtlsRole::Client,
    )?
    .offerer
    .pc
    .create_offer(None)?;

    let mut peer = answerer(SctpSnapMode::Offer)?;
    peer.pc
        .set_remote_description(now, with_sctp_inits(&offer, &[DRAFT_OFFER_SCTP_INIT])?)?;
    assert_eq!(
        sctp_inits(&peer.pc.create_answer(None)?).len(),
        1,
        "an offer with a valid INIT is answered with one"
    );

    // The draft's chunk with its type changed from INIT (1) to INIT ACK (2).
    let init_ack = "AgAAHols3R0AUAAA/////+B5ZR3AAAAEgAgABoLA";
    for (sctp_inits, error) in [
        (vec!["not base64!"], Error::ErrSDPSctpInitNotBase64),
        (vec![init_ack], Error::ErrChunkTypeNotTypeInit),
        (
            vec![DRAFT_OFFER_SCTP_INIT, DRAFT_OFFER_SCTP_INIT],
            Error::ErrSDPSctpInitDuplicated,
        ),
    ] {
        let bad_offer = with_sctp_inits(&offer, &sctp_inits)?;

        let mut peer = answerer(SctpSnapMode::Offer)?;
        assert_eq!(
            peer.pc.set_remote_description(now, bad_offer.clone()),
            Err(error),
            "{sctp_inits:?}"
        );

        let mut peer = answerer(SctpSnapMode::Disabled)?;
        peer.pc
            .set_remote_description(now, bad_offer)
            .expect("a peer with SNAP disabled does not read the attribute");
    }
    Ok(())
}

/// Once the association is started from the INITs, both peers stand by them: each repeats
/// its own in every later description and refuses one from the peer that does not.
#[test]
fn later_descriptions_repeat_the_inits_the_association_was_started_from() -> Result<()> {
    let mut call = Call::connected(SctpSnapMode::Offer, SctpSnapMode::Offer)?;
    let now = call.start;
    let first_offer = call.offerer.pc.local_description().unwrap().clone();
    let first_answer = call.answerer.pc.local_description().unwrap().clone();

    let reoffer = call.offerer.pc.create_offer(None)?;
    assert_eq!(sctp_inits(&reoffer), sctp_inits(&first_offer));

    for (changed, case) in [
        (vec![DRAFT_OFFER_SCTP_INIT], "another INIT"),
        (vec![], "no INIT"),
    ] {
        assert_eq!(
            call.answerer
                .pc
                .set_remote_description(now, with_sctp_inits(&reoffer, &changed)?),
            Err(Error::ErrSDPSctpInitChanged),
            "{case}"
        );
    }

    call.offerer
        .pc
        .set_local_description(now, reoffer.clone())?;
    call.answerer.pc.set_remote_description(now, reoffer)?;
    let reanswer = call.answerer.pc.create_answer(None)?;
    assert_eq!(sctp_inits(&reanswer), sctp_inits(&first_answer));
    call.answerer
        .pc
        .set_local_description(now, reanswer.clone())?;
    call.offerer.pc.set_remote_description(now, reanswer)?;

    assert_eq!(call.offerer.snap_outcome(), RTCSctpSnapOutcome::Used);
    assert_eq!(call.answerer.snap_outcome(), RTCSctpSnapOutcome::Used);
    Ok(())
}

/// An association that came up by handshake cannot be given an INIT afterwards.
#[test]
fn an_sctp_init_added_after_a_handshake_is_refused() -> Result<()> {
    let mut call = Call::connected(SctpSnapMode::Offer, SctpSnapMode::Disabled)?;
    let now = call.start;

    // The answerer has SNAP disabled, so its offer carries no INIT until one is put there.
    let reoffer = call.answerer.pc.create_offer(None)?;
    assert!(sctp_inits(&reoffer).is_empty());
    assert_eq!(
        call.offerer
            .pc
            .set_remote_description(now, with_sctp_inits(&reoffer, &[DRAFT_ANSWER_SCTP_INIT])?),
        Err(Error::ErrSDPSctpInitUnexpected)
    );

    call.offerer.pc.set_remote_description(now, reoffer)?;
    assert!(
        sctp_inits(&call.offerer.pc.create_answer(None)?).is_empty(),
        "the handshake association is not advertised an INIT either"
    );
    Ok(())
}
