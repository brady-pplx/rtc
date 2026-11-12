//! SNAP: SCTP INIT chunks exchanged in SDP, so the association starts without a handshake.
//!
//! Each peer may put its INIT in an `a=sctp-init` attribute of the data section
//! ([draft-hancke-tsvwg-snap]). Only when both did is the association started established,
//! once DTLS is up. [`SnapNegotiation`] is the one owner of where that exchange stands, and
//! [`RTCSctpSnapOutcome`] is what the application reads of it.
//!
//! [draft-hancke-tsvwg-snap]: https://datatracker.ietf.org/doc/draft-hancke-tsvwg-snap/

use crate::peer_connection::configuration::setting_engine::SctpSnapMode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sctp::{LocalInit, RemoteInit, TransportConfig};
use sdp::MediaDescription;
use shared::error::{Error, Result};

/// The SDP attribute that carries a base64-encoded INIT chunk in the data section.
pub(crate) const ATTR_KEY_SCTP_INIT: &str = "sctp-init";

/// Whether the SCTP handshake was skipped for this transport.
///
/// Read from [`RTCSctpTransport::snap_outcome`](crate::peer_connection::transport::RTCSctpTransport::snap_outcome).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RTCSctpSnapOutcome {
    /// Not decided yet: the offer and answer have not both been applied, or they agreed to
    /// skip the handshake and DTLS has not finished.
    Pending,

    /// The association comes up through the SCTP handshake.
    NotUsed(RTCSctpSnapUnusedReason),

    /// The association was started from the INITs exchanged in SDP; no handshake ran.
    Used,

    /// Both peers advertised an INIT and the association could not be created from them.
    /// The transport carries no association.
    Failed,
}

/// Why the SCTP handshake was not skipped.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RTCSctpSnapUnusedReason {
    /// This endpoint has [`SctpSnapMode::Disabled`].
    Disabled,

    /// The peer's description carried no `a=sctp-init` attribute.
    PeerDidNotOffer,
}

/// Which half of an offer/answer exchange a description is.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DescriptionRole {
    Offer,
    /// A provisional answer included.
    Answer,
}

/// The value of the `a=sctp-init` attribute this endpoint writes: its INIT chunk in base64.
///
/// Only built from a [`LocalInit`], so a description can never carry an INIT the association
/// will not be started from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SctpInitAttribute(String);

impl SctpInitAttribute {
    fn of(init: &LocalInit) -> Self {
        Self(STANDARD.encode(init.chunk_bytes()))
    }

    pub(crate) fn into_value(self) -> String {
        self.0
    }
}

/// How the transport is to bring its association up, decided when it starts.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SctpStart {
    /// By the SCTP handshake.
    Handshake,
    /// From the exchanged INITs once DTLS is up, with no INIT sent or accepted.
    ExchangedInits,
}

/// Where the exchange of INITs stands, from the setting to the started association.
#[derive(Debug)]
pub(crate) enum SnapNegotiation {
    /// [`SctpSnapMode::Disabled`]: nothing is advertised and the peer's attribute is not read.
    Disabled,
    /// The transport has not started. The two halves are independent: either peer may offer
    /// first, and an offer may be rolled back.
    Negotiating {
        /// Generated for the first description to carry it and repeated in every later one.
        local: Option<LocalInit>,
        /// From the remote description last applied, if that carried one.
        peer: Option<RemoteInit>,
    },
    /// Both advertised, and the transport is started and waits for DTLS.
    AwaitingDtls {
        local: LocalInit,
        remote: RemoteInit,
        config: TransportConfig,
    },
    /// The association was started from both INITs.
    Established {
        local: SctpInitAttribute,
        remote: RemoteInit,
    },
    /// One of the peers advertised none, so the SCTP handshake runs.
    Handshake,
    /// Both advertised and the association could not be created.
    Failed,
}

impl SnapNegotiation {
    pub(crate) fn new(mode: SctpSnapMode) -> Self {
        match mode {
            SctpSnapMode::Disabled => Self::Disabled,
            SctpSnapMode::Offer => Self::Negotiating {
                local: None,
                peer: None,
            },
        }
    }

    /// The attribute for the data section of a description this endpoint is writing.
    ///
    /// An offer carries one, generated from `config` the first time. An answer carries one
    /// only if the offer did, as an answer must not introduce it. Once the association is
    /// started from the INITs, every description repeats the one it was started from.
    pub(crate) fn local_attribute(
        &mut self,
        role: DescriptionRole,
        config: &TransportConfig,
    ) -> Option<SctpInitAttribute> {
        match self {
            Self::Negotiating { local, peer } => {
                let advertise = match role {
                    DescriptionRole::Offer => true,
                    DescriptionRole::Answer => peer.is_some(),
                };
                advertise.then(|| {
                    SctpInitAttribute::of(local.get_or_insert_with(|| LocalInit::generate(config)))
                })
            }
            Self::AwaitingDtls { local, .. } => Some(SctpInitAttribute::of(local)),
            Self::Established { local, .. } => Some(local.clone()),
            Self::Disabled | Self::Handshake | Self::Failed => None,
        }
    }

    /// Reads the peer's INIT from the data section of its description and checks it against
    /// the exchange so far. Changes nothing: the description may yet be refused for another
    /// reason, so the result is handed to [`Self::record_peer_init`] once it is applied.
    ///
    /// `None` when the section carries no INIT, or when this endpoint has SNAP disabled, in
    /// which case the attribute is not looked at, valid or not.
    ///
    /// # Errors
    ///
    /// The attribute is an error when it appears twice, is not base64, or does not decode
    /// to a valid INIT chunk. Once the transport has started it is also an error to change
    /// or drop the INIT the association was agreed on, and to add one to an association
    /// that came up by handshake. Replacing the association to negotiate a new INIT is not
    /// supported.
    pub(crate) fn read_peer_init(
        &self,
        data_section: &MediaDescription,
    ) -> Result<Option<RemoteInit>> {
        let rule = match self {
            // `Failed` holds the peer to nothing: there is no association left to protect.
            Self::Disabled | Self::Failed => return Ok(None),
            Self::Negotiating { .. } => PeerInitRule::Any,
            Self::Handshake => PeerInitRule::Absent,
            Self::AwaitingDtls { remote, .. } | Self::Established { remote, .. } => {
                PeerInitRule::Same(remote)
            }
        };

        let peer = parse_sctp_init(data_section)?;
        match (rule, &peer) {
            (PeerInitRule::Any, None | Some(_)) | (PeerInitRule::Absent, None) => Ok(peer),
            (PeerInitRule::Absent, Some(_)) => Err(Error::ErrSDPSctpInitUnexpected),
            (PeerInitRule::Same(agreed), Some(repeated)) if agreed == repeated => Ok(peer),
            (PeerInitRule::Same(_), None | Some(_)) => Err(Error::ErrSDPSctpInitChanged),
        }
    }

    /// Records what [`Self::read_peer_init`] found, once the description is applied.
    pub(crate) fn record_peer_init(&mut self, read: Option<RemoteInit>) {
        match self {
            Self::Negotiating { peer, .. } => *peer = read,
            // After the transport starts a description can only repeat what is held.
            Self::Disabled
            | Self::AwaitingDtls { .. }
            | Self::Established { .. }
            | Self::Handshake
            | Self::Failed => {}
        }
    }

    /// Decides how the association comes up, as the transport starts. `config` is what an
    /// association started from the INITs will run with.
    pub(crate) fn settle(&mut self, config: &TransportConfig) -> SctpStart {
        *self = match std::mem::replace(self, Self::Handshake) {
            Self::Negotiating {
                local: Some(local),
                peer: Some(remote),
            } => Self::AwaitingDtls {
                local,
                remote,
                config: config.clone(),
            },
            Self::Negotiating { .. } => Self::Handshake,
            current @ (Self::Disabled
            | Self::AwaitingDtls { .. }
            | Self::Established { .. }
            | Self::Handshake
            | Self::Failed) => current,
        };
        match self {
            Self::AwaitingDtls { .. } | Self::Established { .. } | Self::Failed => {
                SctpStart::ExchangedInits
            }
            Self::Disabled | Self::Negotiating { .. } | Self::Handshake => SctpStart::Handshake,
        }
    }

    /// Starts the association with `connect` if it waits for DTLS, which the caller has
    /// seen come up. `None` in every other state, so the caller may ask on each sign of it.
    ///
    /// # Errors
    ///
    /// The error of `connect`, after which the negotiation has failed for good.
    pub(crate) fn establish<T>(
        &mut self,
        connect: impl FnOnce(LocalInit, &RemoteInit, TransportConfig) -> Result<T>,
    ) -> Result<Option<T>> {
        match std::mem::replace(self, Self::Failed) {
            Self::AwaitingDtls {
                local,
                remote,
                config,
            } => {
                let advertised = SctpInitAttribute::of(&local);
                let started = connect(local, &remote, config)?;
                *self = Self::Established {
                    local: advertised,
                    remote,
                };
                Ok(Some(started))
            }
            current @ (Self::Disabled
            | Self::Negotiating { .. }
            | Self::Established { .. }
            | Self::Handshake
            | Self::Failed) => {
                *self = current;
                Ok(None)
            }
        }
    }

    pub(crate) fn outcome(&self) -> RTCSctpSnapOutcome {
        match self {
            Self::Disabled => RTCSctpSnapOutcome::NotUsed(RTCSctpSnapUnusedReason::Disabled),
            Self::Handshake => {
                RTCSctpSnapOutcome::NotUsed(RTCSctpSnapUnusedReason::PeerDidNotOffer)
            }
            Self::Negotiating { .. } | Self::AwaitingDtls { .. } => RTCSctpSnapOutcome::Pending,
            Self::Established { .. } => RTCSctpSnapOutcome::Used,
            Self::Failed => RTCSctpSnapOutcome::Failed,
        }
    }
}

/// What a remote description's data section may say about the peer's INIT.
enum PeerInitRule<'a> {
    Any,
    Absent,
    Same(&'a RemoteInit),
}

/// The INIT a data section advertises, if it advertises one.
fn parse_sctp_init(data_section: &MediaDescription) -> Result<Option<RemoteInit>> {
    let mut attributes = data_section
        .attributes
        .iter()
        .filter(|attribute| attribute.key == ATTR_KEY_SCTP_INIT);
    let Some(attribute) = attributes.next() else {
        return Ok(None);
    };
    if attributes.next().is_some() {
        return Err(Error::ErrSDPSctpInitDuplicated);
    }
    let chunk = STANDARD
        .decode(attribute.value.as_deref().unwrap_or_default())
        .map_err(|_| Error::ErrSDPSctpInitNotBase64)?;
    RemoteInit::parse(&chunk).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid INIT to stand for the peer's.
    fn peer_init() -> RemoteInit {
        let init = LocalInit::generate(&TransportConfig::default());
        RemoteInit::parse(&init.chunk_bytes()).expect("a generated INIT is valid")
    }

    // A peer connection starts its transports on the first remote offer and takes no other
    // before it answers, so the offer that withdraws an INIT is only reachable here.
    #[test]
    fn an_offer_that_carries_no_init_withdraws_the_one_before_it() {
        let config = TransportConfig::default();
        let mut snap = SnapNegotiation::new(SctpSnapMode::Offer);
        snap.record_peer_init(Some(peer_init()));

        // The offer was rolled back, or replaced by one without an INIT.
        snap.record_peer_init(None);

        assert!(
            snap.local_attribute(DescriptionRole::Answer, &config)
                .is_none(),
            "an answer must not introduce an INIT"
        );
        assert_eq!(snap.settle(&config), SctpStart::Handshake);
    }

    // No peer connection can make `connect_established` fail: the endpoint is new, so the
    // advertised tag is free. The transition out of that failure is only reachable here.
    #[test]
    fn an_association_that_cannot_be_created_fails_the_negotiation_for_good() {
        let config = TransportConfig::default();
        let mut snap = SnapNegotiation::new(SctpSnapMode::Offer);
        assert!(
            snap.local_attribute(DescriptionRole::Offer, &config)
                .is_some()
        );
        snap.record_peer_init(Some(peer_init()));
        assert_eq!(snap.settle(&config), SctpStart::ExchangedInits);

        let refused: Result<Option<()>> =
            snap.establish(|_, _, _| Err(Error::ErrSCTPAssociationFromInitNotCreated));

        assert_eq!(refused, Err(Error::ErrSCTPAssociationFromInitNotCreated));
        assert_eq!(snap.outcome(), RTCSctpSnapOutcome::Failed);
        assert_eq!(
            snap.establish(|_, _, _| Ok(())),
            Ok(None),
            "the INIT was spent on the failed attempt"
        );
        assert!(
            snap.local_attribute(DescriptionRole::Offer, &config)
                .is_none()
        );
    }
}
