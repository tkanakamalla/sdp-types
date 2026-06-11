// Copyright (C) 2026 Taruntej Kanakamalla <tarun@centricular.com>
//
// Licensed under the MIT license, see the LICENSE file or <http://opensource.org/licenses/MIT>

//! Contains all the helper enums used by a Session, Media and other Attribute structs

use std::{fmt::Display, str::FromStr};

use crate::attributes::SrtpKeyParam;

/// Errors while parsing strings to Enum
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ParseEnumError {
    Invalid(String),
}

impl std::error::Error for ParseEnumError {}

impl std::fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseEnumError::Invalid(s) => {
                write!(f, "Failed to parse {s} as an enum type")
            }
        }
    }
}

/// Type of network of the originator or a connection of the session.
///
/// See [RFC 8866 Section 5.2](https://tools.ietf.org/html/rfc8866#section-5.2),
/// [RFC 8866 Section 5.7](https://tools.ietf.org/html/rfc8866#section-5.7) and
/// [RFC 8866 Section 8.2.6](https://datatracker.ietf.org/doc/html/rfc8866#section-8.2.6) for more details
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NetType {
    /// Internet
    In,
    /// Telephone Network
    Tn,
    /// ATM Bearer Connection
    Atm,
    /// Public Switched Telephone Network
    Pstn,
}

impl NetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetType::In => "IN",
            NetType::Tn => "TN",
            NetType::Atm => "ATM",
            NetType::Pstn => "PSTN",
        }
    }
}

impl FromStr for NetType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "IN" => Ok(NetType::In),
            "TN" => Ok(NetType::Tn),
            "ATM" => Ok(NetType::Atm),
            "PSTN" => Ok(NetType::Pstn),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for NetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of address of the originator or a connection of the session
///
/// See [RFC 8866 Section 5.2](https://tools.ietf.org/html/rfc8866#section-5.2),
/// [RFC 8866 Section 5.7](https://tools.ietf.org/html/rfc8866#section-5.7)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AddrType {
    /// IPv4 address
    Ip4,
    /// Ipv6 address
    Ip6,
}

impl AddrType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddrType::Ip4 => "IP4",
            AddrType::Ip6 => "IP6",
        }
    }
}

impl FromStr for AddrType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "IP4" => Ok(AddrType::Ip4),
            "IP6" => Ok(AddrType::Ip6),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for AddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of the Bandwidth value.
///
/// See [RFC 8866 Section 5.8](https://tools.ietf.org/html/rfc8866#section-5.8) for more details.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BandwidthType {
    /// Conference total - maximum bandwith a session will use
    Ct,
    /// Application Specific maximum bandwidth
    As,
    /// Bandwidth assigned for RTCP reports by active senders. See [RFC 3890 Section 1.1.3](https://datatracker.ietf.org/doc/html/rfc3890#section-1.1.3)
    Rr,
    /// Bandwidth assigned for RTCP reports by active receivers. See [RFC 3890 Section 1.1.3](https://datatracker.ietf.org/doc/html/rfc3890#section-1.1.3)
    Rs,
}

impl BandwidthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BandwidthType::As => "AS",
            BandwidthType::Ct => "CT",
            BandwidthType::Rr => "RR",
            BandwidthType::Rs => "RS",
        }
    }
}

impl FromStr for BandwidthType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "AS" => Ok(BandwidthType::As),
            "CT" => Ok(BandwidthType::Ct),
            "RR" => Ok(BandwidthType::Rr),
            "RS" => Ok(BandwidthType::Rs),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for BandwidthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Method of encryption (Obselete)
///
/// Note: This field is obsolete and and MUST NOT be used. It is included in only for legacy reasons
/// See [RFC 8866 Section 5.12](https://datatracker.ietf.org/doc/html/rfc8866#section-5.12)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyMethod {
    /// Untransformed
    Clear,
    /// Base64 encoded
    Base64,
    /// URI to obtain the key
    Uri,
    /// User should be prompted for the key
    Prompt,
}

impl KeyMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyMethod::Clear => "clear",
            KeyMethod::Base64 => "base64",
            KeyMethod::Uri => "uri",
            KeyMethod::Prompt => "prompt",
        }
    }
}

impl FromStr for KeyMethod {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // case-sensitive
        match s {
            "clear" => Ok(KeyMethod::Clear),
            "base64" => Ok(KeyMethod::Base64),
            "uri" => Ok(KeyMethod::Uri),
            "prompt" => Ok(KeyMethod::Prompt),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for KeyMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The media type
///
/// See [RFC 8866 Section 5.14](https://datatracker.ietf.org/doc/html/rfc8866#section-5.14)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MediaType {
    /// Audio type
    Audio,
    /// Video type
    Video,
    /// Text type
    Text,
    /// Application type
    Application,
    /// Message type
    Message,
    /// Image type. See [RFC 6466](https://datatracker.ietf.org/doc/html/rfc6466)
    Image,
}

impl MediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::Audio => "audio",
            MediaType::Video => "video",
            MediaType::Text => "text",
            MediaType::Application => "application",
            MediaType::Message => "message",
            MediaType::Image => "image",
        }
    }
}

impl FromStr for MediaType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "audio" => Ok(MediaType::Audio),
            "video" => Ok(MediaType::Video),
            "text" => Ok(MediaType::Text),
            "application" => Ok(MediaType::Application),
            "message" => Ok(MediaType::Message),
            "image" => Ok(MediaType::Image),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Transport Protocol for the media
///
/// See [RFC 8866 Section 5.14](https://datatracker.ietf.org/doc/html/rfc8866#section-5.14)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TransportProto {
    /// Direct UDP
    Udp,
    /// RTP over UDP
    RtpAvp,
    /// Secure RTP over UDP
    RtpSavp,
    /// Secure RTP over UDP with RTCP-based feedback
    RtpSavpf,
}

impl TransportProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            // The strings are case-insensitive, but the spec (RFC 8866) uses lower-case of the "udp" protocol
            // and upper-case for the others so keeping it the same
            TransportProto::Udp => "udp",
            TransportProto::RtpAvp => "RTP/AVP",
            TransportProto::RtpSavp => "RTP/SAVP",
            TransportProto::RtpSavpf => "RTP/SAVPF",
        }
    }
}

impl FromStr for TransportProto {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The strings are case-insensitive, but the spec (RFC 8866) uses lower-case of the "udp" protocol
        // and upper-case for the others so keeping it the same
        if "udp".eq_ignore_ascii_case(s) {
            Ok(TransportProto::Udp)
        } else if "RTP/AVP".eq_ignore_ascii_case(s) {
            Ok(TransportProto::RtpAvp)
        } else if "RTP/SAVP".eq_ignore_ascii_case(s) {
            Ok(TransportProto::RtpSavp)
        } else if "RTP/SAVPF".eq_ignore_ascii_case(s) {
            Ok(TransportProto::RtpSavpf)
        } else {
            Err(ParseEnumError::Invalid(s.to_string()))
        }
    }
}

impl Display for TransportProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Secure Hash functions
///
#[derive(Debug, Clone, PartialEq)]
pub enum HashFunc {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    MD5,
    MD2,
    Other(String),
}

/// Semantics for Group Attribute
///
#[derive(Debug, Clone, PartialEq)]
pub enum GroupSemantics {
    /// Lip Synchronization
    ///
    /// See [RFC 5888 Section 7](https://datatracker.ietf.org/doc/html/rfc5888#section-7)
    LS,
    /// Flow Identification
    ///
    /// See [RFC 5888 Section 8](https://datatracker.ietf.org/doc/html/rfc5888#section-8)
    FID,
    /// Single Reservation Flow
    ///
    /// See [RFC 3524 Section 2](https://datatracker.ietf.org/doc/html/rfc3524#section-2)
    SRF,
    /// Alternative Network Address Types
    ///
    /// See [RFC 4091 Section 3](https://datatracker.ietf.org/doc/html/rfc4091#section-3)
    ANAT,
    /// Forward Error Correction
    ///
    /// See [RFC 4756 Section 4](https://datatracker.ietf.org/doc/html/rfc4756#section-4)
    FEC,
    /// Decoding Dependency
    ///
    /// See [RFC 5582 Section 5.2.1](https://datatracker.ietf.org/doc/html/rfc5583#section-5.2.1)
    DDP,
    /// Other Semantics
    Other(String),
}

/// Encryption and authentication algorithms for Crypto attribute
///
/// See [RFC 4568 Section 10.3.2](https://datatracker.ietf.org/doc/html/rfc4568#section-10.3.2)
///
/// Note: `F8_128_HMAC_SHA1_32` appears in the [RFC 4568 Section 9.2](https://datatracker.ietf.org/doc/html/rfc4568#section-9.2)
/// grammar but was never registered in the IANA registry, so it is not defined as a variant here.
/// It will be parsed as `Other`.
#[derive(Debug, PartialEq, Clone)]
pub enum CryptoSuite {
    /// AES_CM_128_HMAC_SHA1_80
    AesCm128HmacSha1_80,
    /// AES_CM_128_HMAC_SHA1_32
    AesCm128HmacSha1_32,
    /// F8_128_HMAC_SHA1_80
    F8_128HmacSha1_80,
    /// Other Crypto Suite
    Other(String),
}

/// Signals whether FEC is applied before or after SRTP processing
///
/// See [RFC 4568 Section 6.3.5](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.5)
#[derive(Debug, PartialEq, Clone)]
pub enum FecOrder {
    /// FEC is applied before SRTP processing
    FecSrtp,
    /// FEC is applied after SRTP processing
    SrtpFec,
}

/// SRTP session parameters
///
/// See [RFC 4568 Section 6.3](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3)
#[derive(Debug, PartialEq, Clone)]
pub enum SrtpSessionParam {
    /// Key Derivation Rate
    ///
    /// See [RFC 4568 Section 6.3.1](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.1)
    Kdr(u8),
    /// Signals that the SRTP packets are without encryption
    ///
    /// See [RFC 4568 Section 6.3.2](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.2)
    UnencryptedSrtp,
    /// Signals that the SRTCP packets are without encryption
    ///
    /// See [RFC 4568 Section 6.3.2](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.2)
    UnencryptedSrtcp,
    /// Signals that the SRTP packets are not authenticated. (Not recommended)
    ///
    /// See [RFC 4568 Section 6.3.3](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.3)
    UnauthenticatedSrtp,
    /// Signals whether FEC is applied before or after SRTP processing
    ///
    /// See [RFC 4568 Section 6.3.4](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.4)
    FecOrder(FecOrder),
    /// Signals the use of separate master key(s) for forward error correction
    ///
    /// See [RFC 4568 Section 6.3.5](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.5)
    FecKey(Vec<SrtpKeyParam>),
    /// Window Size Hint - provides a hint for how big the SRTP Window size should be
    ///
    /// See [RFC 4568 Section 6.3.6](https://datatracker.ietf.org/doc/html/rfc4568#section-6.3.6)
    Wsh(u8),
    /// Unknown parameter
    Extension(String),
}

/// Type of the Candidate
///
#[derive(Debug, PartialEq, Clone)]
pub enum CandidateType {
    /// Host
    Host,
    /// Server-reflexive
    Srflx,
    /// Peer-reflexive
    Prflx,
    /// Relay
    Relay,
    /// Unknown type
    Other(String),
}

/// RTCP Positive feedback values
///
/// See [RFC 4585 Section 4.2](https://datatracker.ietf.org/doc/html/rfc4585#section-4.2)
#[derive(Debug, PartialEq, Clone)]
pub enum RtcpFbAck {
    /// Reference Picture Selection Indication
    Rpsi,
    /// Application layer feedback
    App(Option<String>),
    /// Congestion Control Feedback
    ///
    /// See [RFC 8888 Section 6](https://datatracker.ietf.org/doc/html/rfc8888#section-6)
    Ccfb,
    /// Other Ack types
    Other(String),
}

/// RTCP Negative feedback values
///
/// See [RFC 4585 Section 4.2](https://datatracker.ietf.org/doc/html/rfc4585#section-4.2)
#[derive(Debug, PartialEq, Clone)]
pub enum RtcpFbNack {
    /// Picture Loss Indication
    Pli,
    /// Slice Loss Indication
    Sli,
    /// Reference Picture Selection Indication
    Rpsi,
    /// Application layer feedback
    App(Option<String>),
    /// Explicit Congestion Notification
    ///
    /// See [RFC 6679 Section 6.2](https://datatracker.ietf.org/doc/html/rfc6679#section-6.2)
    Ecn,
    /// Other Nack types
    Other(String),
}

/// Codec Control using RTCP feedback messages
///
/// See [RFC 5104 Section 7.1](https://datatracker.ietf.org/doc/html/rfc5104#section-7.1)
#[derive(Debug, PartialEq, Clone)]
pub enum RtcpFbCcm {
    /// Full Intra Request
    Fir,
    /// Temporary Maximum Media Stream Bit Rate
    Tmmbr(Option<String>),
    /// Temporal-Spatial Trade-off
    Tstr,
    /// Video Back Channel Messages
    Vbcm(Vec<u8>),
    /// Other messages (for future commands/Indications)
    Other(String),
}

#[derive(Debug, PartialEq, Clone)]
/// Types of RTCP feedback values
pub enum RtcpFbVal {
    /// Positive Acknowledgement
    Ack(Option<RtcpFbAck>),
    /// Negative Acknowledgement
    Nack(Option<RtcpFbNack>),
    /// Minimum interval between two Regular RTCP packets in milliseconds
    TrrInt(u64),
    /// Codec Control messages
    Ccm(RtcpFbCcm),
    /// Others Rtcp Fb types
    Other(String),
}

impl Display for RtcpFbVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fb_val = match self {
            RtcpFbVal::Ack(ack) => {
                let mut s = "ack".to_string();
                if let Some(ack) = ack {
                    match ack {
                        RtcpFbAck::Rpsi => s += " rpsi",
                        RtcpFbAck::Ccfb => s += " ccfb",
                        RtcpFbAck::App(app) => {
                            s += " app";
                            if let Some(app_param) = app {
                                s += format!(" {}", app_param).as_str();
                            }
                        }
                        RtcpFbAck::Other(other) => {
                            s += format!(" {}", other).as_str();
                        }
                    }
                }
                s
            }
            RtcpFbVal::Nack(nack) => {
                let mut s = "nack".to_string();
                if let Some(nack) = nack {
                    match nack {
                        RtcpFbNack::Pli => s += " pli",
                        RtcpFbNack::Sli => s += " sli",
                        RtcpFbNack::Rpsi => s += " rpsi",
                        RtcpFbNack::Ecn => s += " ecn",
                        RtcpFbNack::App(app) => {
                            s += " app";
                            if let Some(app_param) = app {
                                s += format!(" {}", app_param).as_str();
                            }
                        }
                        RtcpFbNack::Other(other) => {
                            s += format!(" {}", other).as_str();
                        }
                    }
                }
                s
            }
            RtcpFbVal::TrrInt(trr_int) => {
                format!("trr-int {}", trr_int)
            }
            RtcpFbVal::Ccm(ccm) => {
                let mut s = "ccm".to_string();
                match ccm {
                    RtcpFbCcm::Fir => s += " fir",
                    RtcpFbCcm::Tstr => s += " tstr",
                    RtcpFbCcm::Tmmbr(smaxpr) => {
                        s += " tmmbr";
                        if let Some(smaxpr) = smaxpr {
                            s += format!(" {}", smaxpr).as_str();
                        }
                    }
                    RtcpFbCcm::Vbcm(vbcm) => {
                        s += " vbcm";
                        vbcm.iter().for_each(|v| {
                            s += format!(" {}", v).as_str();
                        });
                    }
                    RtcpFbCcm::Other(other) => {
                        s += format!(" {}", other).as_str();
                    }
                }
                s
            }
            RtcpFbVal::Other(other) => other.clone(),
        };

        f.write_str(&fb_val)
    }
}

/// Source attribute types
///
#[derive(Debug, Clone, PartialEq)]
pub enum SsrcAttribute {
    /// See [RFC 5576 Section 6.1](https://tools.ietf.org/html/rfc5576#section-6.1)
    Cname,
    /// See [RFC 5576 Section 6.2](https://tools.ietf.org/html/rfc5576#section-6.2)
    PreviousSsrc,
    /// See [RFC 5576 Section 6.3](https://tools.ietf.org/html/rfc5576#section-6.3)
    Fmtp,
    /// See [RFC 5576 Section 6.4](https://tools.ietf.org/html/rfc5576#section-6.4)
    Other(String),
}

/// Payload format for which feedback messages may be used,
#[derive(Debug, PartialEq, Clone)]
pub enum RtcpFbPt {
    /// Fixed payload format
    Fmt(u8),
    /// Applies to all formats
    Wildcard,
}

/// Candidate connection address type
///
/// Can be IPv4, IPv6 or a FQDN
#[derive(Debug, PartialEq, Clone)]
pub enum CandidateAddress {
    IpAddr(std::net::IpAddr),
    FQDN(String),
}
