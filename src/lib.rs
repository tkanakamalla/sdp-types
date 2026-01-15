// Copyright (C) 2019 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the MIT license, see the LICENSE file or <http://opensource.org/licenses/MIT>

//! Crate for handling SDP ([RFC 8866](https://tools.ietf.org/html/rfc8866))
//! session descriptions, including a parser and serializer.
//!
//! ## Serializing an SDP
//!
//! ```rust,ignore
//! // Create SDP session description
//! let sdp = sdp_types::Session {
//!     ...
//! };
//!
//! // And write it to an `Vec<u8>`
//! let mut output = Vec::new();
//! sdp.write(&mut output).unwrap();
//! ```
//!
//! ## Parsing an SDP
//!
//! ```rust,no_run
//! # let data = [0u8];
//! // Parse SDP session description from a byte slice
//! let sdp = sdp_types::Session::parse(&data).unwrap();
//!
//! // Access the 'tool' attribute
//! match sdp.get_first_attribute_value("tool") {
//!     Ok(Some(tool)) => println!("tool: {}", tool),
//!     Ok(None) => println!("tool: empty"),
//!     Err(_) => println!("no tool attribute"),
//! }
//!
//! // Access all the 'rtpmap' attributes as a `RtpMap` type
//! // returns an iterator of type `Iterator<Item = Result<RtpMap, AttributeErr>>`
//! let r = sdp.attributes_typed::<sdp_types::RtpMap>();
//! ```
//!
//! ## Limitations
//!
//!  * SDP session descriptions are by default in UTF-8 but an optional `charset`
//!    attribute can change this for various SDP fields, including various other
//!    attributes. This is currently not supported, only UTF-8 is supported.
//!
//!  * Network addresses, Phone numbers, E-Mail addresses and various other fields
//!    are currently parsed as a plain string and not according to the SDP
//!    grammar.

use std::{
    fmt::Display,
    net::{AddrParseError, IpAddr},
    str::FromStr,
};

use bstr::*;
use fallible_iterator::FallibleIterator;

mod parser;
mod writer;

pub use parser::ParserError;

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

/// Trait for Typed Attribute structs
pub trait TypedAttribute: Display + FromStr<Err = AttributeErr> {
    const NAME: &'static str;
}

/// RtpMap Attribute
///
/// See [RFC 8866 Section 6.6](https://datatracker.ietf.org/doc/html/rfc8866#section-6.6) for more details
#[derive(Debug, Clone, PartialEq)]
pub struct RtpMap {
    /// Payload type, a numerical value between 0 and 127
    pub payload_type: u8,
    /// Name of the encoding
    // TODO: is it useful to have an enum for all known encoding?
    pub encoding_name: String,
    /// Clock rate
    pub clock_rate: u32,
    /// Encoding parameters.
    ///
    /// Currently used only for audio channel count
    pub encoding_params: Option<String>,
}

impl FromStr for RtpMap {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((pt, rest)) = s.split_once(' ') else {
            return Err(AttributeErr("Failed to split the rtpmap using a space"));
        };

        let Ok(pt) = pt.parse::<u8>() else {
            return Err(AttributeErr("Failed to parse payload type in rtpmap"));
        };

        if pt > 127 {
            return Err(AttributeErr("payload type value out of valid range(0-127)"));
        }

        let mut i = rest.splitn(3, '/');
        let Some(encoding) = i.next() else {
            return Err(AttributeErr("Failed to get encoding name in the rtpmap"));
        };

        let Some(clock_rate) = i.next() else {
            return Err(AttributeErr("Failed to get clock rate in the rtpmap"));
        };

        let Ok(clock_rate) = clock_rate.parse::<u32>() else {
            return Err(AttributeErr("Failed to parse clock rate in rtpmap"));
        };

        let params = i.next().map(String::from);

        Ok(Self {
            payload_type: pt,
            encoding_name: encoding.to_owned(),
            clock_rate,
            encoding_params: params,
        })
    }
}

impl Display for RtpMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!(
            "{} {}/{}",
            self.payload_type, self.encoding_name, self.clock_rate
        );
        if let Some(params) = &self.encoding_params {
            s += format!("/{params}").as_str();
        }
        f.write_str(&s)
    }
}

impl TypedAttribute for RtpMap {
    const NAME: &'static str = "rtpmap";
}

/// Format specific parameters
#[derive(Debug, Clone, PartialEq)]
pub struct FmtpParam {
    param: String,
    val: Option<String>,
}

/// Format Parameters
///
/// See [RFC 8866 Section 6.15](https://datatracker.ietf.org/doc/html/rfc8866#section-6.15) for more details
#[derive(Debug, Clone, PartialEq)]
pub struct Fmtp {
    /// Payload format
    pub fmt: u8,
    /// Format specific parameters
    // Multiple params are expected to be semicolon separated
    // Each param can be a 'key=value' pair or just single parameter
    pub format_specific_params: Vec<FmtpParam>,
}

impl FromStr for Fmtp {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((fmt, rest)) = s.split_once(' ') else {
            return Err(AttributeErr("Failed to split the format using a space"));
        };

        let Ok(fmt) = fmt.parse::<u8>() else {
            return Err(AttributeErr("Failed to parse format in fmtp"));
        };

        let mut params: Vec<FmtpParam> = Vec::new();
        for param in rest.split(';') {
            if let Some((key, value)) = param.split_once('=') {
                params.push(FmtpParam {
                    param: key.to_string(),
                    val: Some(value.to_string()),
                });
            } else {
                params.push(FmtpParam {
                    param: param.to_string(),
                    val: None,
                });
            }
        }

        Ok(Self {
            fmt,
            format_specific_params: params,
        })
    }
}

impl Display for Fmtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{} ", self.fmt);
        for p in &self.format_specific_params {
            s += p.param.as_str();
            if let Some(val) = &p.val {
                s += format!("={val}").as_str();
            }
            s += ";";
        }
        let s = s.trim_end_matches(';').to_string();
        f.write_str(&s)
    }
}

impl TypedAttribute for Fmtp {
    const NAME: &'static str = "fmtp";
}

/// RTCP port number and address
///
/// To be used if not algorithmically derived
/// from the RTP port described in the media line
///
/// See [RFC 3605 Section 2.1](https://datatracker.ietf.org/doc/html/rfc3605#section-2.1)
#[derive(Debug, Clone, PartialEq)]
pub struct Rtcp {
    /// Port used for the media stream
    pub port: u16,
    /// Network Type
    pub nettype: NetType,
    /// Address type
    pub addrtype: AddrType,
    /// IP Address, unicast or multicast
    pub connection_address: IpAddr,
}

impl FromStr for Rtcp {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');
        let Some(port) = i.next() else {
            return Err(AttributeErr(
                "No values for rtcp attribute, failed to get port number",
            ));
        };

        let Ok(port) = port.parse::<u16>() else {
            return Err(AttributeErr("Failed to parse port in rtcp"));
        };

        let Some(nettype) = i.next() else {
            return Err(AttributeErr(
                "No values for rtcp attribute, failed to get network type",
            ));
        };

        let Ok(nettype) = NetType::from_str(nettype) else {
            return Err(AttributeErr("Failed to parse network type in rtcp"));
        };

        let Some(addrtype) = i.next() else {
            return Err(AttributeErr(
                "No values for rtcp attribute, failed to get address type",
            ));
        };

        let Ok(addrtype) = AddrType::from_str(addrtype) else {
            return Err(AttributeErr("Failed to parse address type in rtcp"));
        };

        let Some(connection_addr) = i.next() else {
            return Err(AttributeErr(
                "No values for rtcp attribute, failed to get connection address",
            ));
        };

        let Ok(connection_address) = connection_addr.parse() else {
            return Err(AttributeErr("Failed to parse connection address in rtcp"));
        };

        Ok(Self {
            port,
            nettype,
            addrtype,
            connection_address,
        })
    }
}

impl Display for Rtcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!(
            "{} {} {} {}",
            self.port, self.nettype, self.addrtype, self.connection_address
        );
        f.write_str(&s)
    }
}

impl TypedAttribute for Rtcp {
    const NAME: &'static str = "rtcp";
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

/// Payload format for which feedback messages may be used,
#[derive(Debug, PartialEq, Clone)]
pub enum RtcpFbPt {
    /// Fixed payload format
    Fmt(u8),
    /// Applies to all formats
    Wildcard,
}

/// RTCP Feedback Capability
///
/// See [RFC 4585 Section 4.2](https://datatracker.ietf.org/doc/html/rfc4585#section-4.2)
pub struct RtcpFb {
    /// Payload format for which feedback messages may be used,
    pub pt: RtcpFbPt,
    /// RTCP Feedback value
    pub val: RtcpFbVal,
}

impl FromStr for RtcpFb {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');
        let Some(pt) = i.next() else {
            return Err(AttributeErr(
                "Failed to parse the RtcpFb, no payload format",
            ));
        };

        let pt = if let Ok(pt) = pt.parse::<u8>() {
            RtcpFbPt::Fmt(pt)
        } else if pt == "*" {
            RtcpFbPt::Wildcard
        } else {
            return Err(AttributeErr(
                "Failed to parse the RtcpFb, invalid values in the payload format",
            ));
        };

        let Some(val) = i.next() else {
            return Err(AttributeErr("Failed to parse the RtcpFb, no Rtcp value"));
        };

        let rtcp_fb_val = match val {
            "ack" => {
                if let Some(ack_val) = i.next() {
                    let ack_val = match ack_val {
                        "rpsi" => RtcpFbAck::Rpsi,
                        "app" => {
                            if let Some(app_param) = i.next() {
                                RtcpFbAck::App(Some(app_param.to_string()))
                            } else {
                                RtcpFbAck::App(None)
                            }
                        }
                        "ccfb" => {
                            // The payload type used with "ccfb" feedback MUST be the wildcard type
                            // See https://datatracker.ietf.org/doc/html/rfc8888#section-6
                            if let RtcpFbPt::Fmt(_) = pt {
                                return Err(AttributeErr("The payload type used with \"ccfb\" feedback is not wildcard type '*'"));
                            } else {
                                RtcpFbAck::Ccfb
                            }
                        }
                        other => RtcpFbAck::Other(other.to_string()),
                    };
                    RtcpFbVal::Ack(Some(ack_val))
                } else {
                    RtcpFbVal::Ack(None)
                }
            }
            "nack" => {
                if let Some(nack_val) = i.next() {
                    let nack_val = match nack_val {
                        "pli" => RtcpFbNack::Pli,
                        "sli" => RtcpFbNack::Sli,
                        "rpsi" => RtcpFbNack::Rpsi,
                        "app" => {
                            if let Some(app_param) = i.next() {
                                RtcpFbNack::App(Some(app_param.to_string()))
                            } else {
                                RtcpFbNack::App(None)
                            }
                        }
                        "ecn" => RtcpFbNack::Ecn,
                        other => RtcpFbNack::Other(other.to_string()),
                    };
                    RtcpFbVal::Nack(Some(nack_val))
                } else {
                    RtcpFbVal::Nack(None)
                }
            }
            "trr-int" => {
                if let Some(val) = i.next() {
                    let Ok(i) = val.parse::<u64>() else {
                        return Err(AttributeErr("Failed to parse trr-int value"));
                    };
                    RtcpFbVal::TrrInt(i)
                } else {
                    return Err(AttributeErr("The trr-int has no value"));
                }
            }
            "ccm" => {
                if let Some(ccm_val) = i.next() {
                    let ccm_val = match ccm_val {
                        "fir" => RtcpFbCcm::Fir,
                        "tmmbr" => {
                            if let Some(tmmbr_val) = i.next() {
                                RtcpFbCcm::Tmmbr(Some(tmmbr_val.to_string()))
                            } else {
                                RtcpFbCcm::Tmmbr(None)
                            }
                        }
                        "tstr" => RtcpFbCcm::Tstr,
                        "vbcm" => {
                            let mut v = vec![];
                            for vbcm_val in i {
                                let Ok(p) = vbcm_val.parse::<u8>() else {
                                    return Err(AttributeErr("Failed to parse vbcm value"));
                                };
                                v.push(p);
                            }
                            RtcpFbCcm::Vbcm(v)
                        }
                        other => RtcpFbCcm::Other(other.to_string()),
                    };
                    RtcpFbVal::Ccm(ccm_val)
                } else {
                    return Err(AttributeErr("Ccm param not available "));
                }
            }
            other => RtcpFbVal::Other(other.to_string()),
        };

        Ok(Self {
            pt,
            val: rtcp_fb_val,
        })
    }
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

impl Display for RtcpFb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pt {
            RtcpFbPt::Wildcard => write!(f, "* ")?,
            RtcpFbPt::Fmt(pt) => write!(f, "{pt} ")?,
        }
        write!(f, "{}", self.val)
    }
}

impl TypedAttribute for RtcpFb {
    const NAME: &'static str = "rtcp-fb";
}

/// Media Direction Attributes
///
/// See [RFC 8866 Section 6.7](https://www.rfc-editor.org/rfc/rfc8866.html#section-6.7)
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    SendOnly,
    RecvOnly,
    SendRecv,
    Inactive,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::SendRecv => "sendrecv",
            Self::Inactive => "inactive",
        }
    }
}

impl FromStr for Direction {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sendonly" => Ok(Direction::SendOnly),
            "recvonly" => Ok(Direction::RecvOnly),
            "sendrecv" => Ok(Direction::SendRecv),
            "inactive" => Ok(Direction::Inactive),
            _ => Err(ParseEnumError::Invalid(s.to_string())),
        }
    }
}

impl Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
/// RTP header extensions map
///
/// See [RFC 8285 Section 8](https://datatracker.ietf.org/doc/html/rfc8285#section-8)
pub struct ExtMap {
    /// The local identifier (ID) of this extension
    pub id: u8,
    /// Direction
    pub direction: Option<Direction>,
    /// The format and meaning of the extension
    pub uri: String,
    /// Extension attributes
    pub attributes: Option<String>,
}

impl FromStr for ExtMap {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.splitn(3, ' ');

        let Some(id_direction) = i.next() else {
            return Err(AttributeErr(
                "Failed to parse the ExtMap, id/direction not present",
            ));
        };

        let mut d = id_direction.split('/');

        let Some(id) = d.next() else {
            return Err(AttributeErr("Failed to parse the ExtMap, id not present"));
        };

        let direction = if let Some(d) = d.next() {
            let Ok(dir) = Direction::from_str(d) else {
                return Err(AttributeErr(
                    "Failed to parse the ExtMap, invalid direction",
                ));
            };
            Some(dir)
        } else {
            None
        };

        let Ok(id) = id.parse::<u8>() else {
            return Err(AttributeErr(
                "Failed to parse the ExtMap, invalid value for id",
            ));
        };

        let Some(uri) = i.next() else {
            return Err(AttributeErr("Failed to parse the ExtMap, no URI present"));
        };

        let attributes = i.next().map(|attr| attr.to_string());

        Ok(Self {
            id,
            direction,
            uri: uri.to_string(),
            attributes,
        })
    }
}

impl Display for ExtMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = self.id.to_string();
        if let Some(direction) = &self.direction {
            s += format!("/{}", direction.as_str()).as_str();
        }

        s += format!(" {}", self.uri).as_str();
        if let Some(attr) = &self.attributes {
            s += format!(" {}", attr).as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for ExtMap {
    const NAME: &'static str = "extmap";
}

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

/// Fingerprint Attribute
///
/// See [RFC 8122 Section 5](https://datatracker.ietf.org/doc/html/rfc8122#section-5)
#[derive(Debug, Clone, PartialEq)]
pub struct Fingerprint {
    /// Name of hash function used
    pub hash_func: HashFunc,
    /// Hash value
    pub fingerprint: Vec<u8>,
}

impl FromStr for Fingerprint {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.splitn(2, ' ');

        let hash_func = if let Some(hash_func) = i.next() {
            if hash_func.eq_ignore_ascii_case("sha-1") {
                HashFunc::SHA1
            } else if hash_func.eq_ignore_ascii_case("sha-224") {
                HashFunc::SHA224
            } else if hash_func.eq_ignore_ascii_case("sha-256") {
                HashFunc::SHA256
            } else if hash_func.eq_ignore_ascii_case("sha-384") {
                HashFunc::SHA384
            } else if hash_func.eq_ignore_ascii_case("sha-512") {
                HashFunc::SHA512
            } else if hash_func.eq_ignore_ascii_case("md-5") {
                HashFunc::MD5
            } else if hash_func.eq_ignore_ascii_case("md-2") {
                HashFunc::MD2
            } else {
                HashFunc::Other(hash_func.to_string())
            }
        } else {
            return Err(AttributeErr(
                "Failed to parse Fingerprint, hash function not found",
            ));
        };

        let mut fingerprint: Vec<u8> = vec![];
        if let Some(fp) = i.next() {
            for f in fp.split(':') {
                let Ok(mut f) = hex::decode(f) else {
                    return Err(AttributeErr(
                        "Failed to parse Fingerprint, hash value is not hex",
                    ));
                };

                fingerprint.append(&mut f);
            }
        } else {
            return Err(AttributeErr(
                "Failed to parse Fingerprint, hash value not found",
            ));
        };

        Ok(Self {
            hash_func,
            fingerprint,
        })
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = match &self.hash_func {
            HashFunc::SHA1 => "sha-1".to_string(),
            HashFunc::SHA224 => "sha-224".to_string(),
            HashFunc::SHA256 => "sha-256".to_string(),
            HashFunc::SHA384 => "sha-384".to_string(),
            HashFunc::SHA512 => "sha-512".to_string(),
            HashFunc::MD5 => "md-5".to_string(),
            HashFunc::MD2 => "md-2".to_string(),
            HashFunc::Other(s) => s.clone(),
        };

        let mut first = true;
        for v in &self.fingerprint {
            if first {
                s += " ";
                first = false;
            } else {
                s += ":";
            }

            s += format!("{:X}", v).as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for Fingerprint {
    const NAME: &'static str = "fingerprint";
}

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

/// Group Attribute
///
/// See [RFC 5888 Section 5](https://datatracker.ietf.org/doc/html/rfc5888#section-5)
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub semantics: GroupSemantics,
    pub mid_tags: Vec<String>,
}

impl FromStr for Group {
    type Err = AttributeErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');

        let Some(semantics) = i.next() else {
            return Err(AttributeErr(
                "Failed to parse Group, semantics not available",
            ));
        };

        let semantics = if "LS".eq_ignore_ascii_case(semantics) {
            GroupSemantics::LS
        } else if "FID".eq_ignore_ascii_case(semantics) {
            GroupSemantics::FID
        } else if "SRF".eq_ignore_ascii_case(semantics) {
            GroupSemantics::SRF
        } else if "ANAT".eq_ignore_ascii_case(semantics) {
            GroupSemantics::ANAT
        } else if "FEC".eq_ignore_ascii_case(semantics) {
            GroupSemantics::FEC
        } else if "DDP".eq_ignore_ascii_case(semantics) {
            GroupSemantics::DDP
        } else {
            GroupSemantics::Other(semantics.to_string())
        };

        let mut mid_tags = vec![];
        for mid in i {
            mid_tags.push(mid.to_string());
        }

        if mid_tags.is_empty() {
            return Err(AttributeErr(
                "Failed to parse Group, media identification tags not available",
            ));
        }

        Ok(Self {
            semantics,
            mid_tags,
        })
    }
}

impl Display for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = match &self.semantics {
            GroupSemantics::LS => "LS".to_string(),
            GroupSemantics::FID => "FS".to_string(),
            GroupSemantics::SRF => "SRF".to_string(),
            GroupSemantics::ANAT => "ANAT".to_string(),
            GroupSemantics::DDP => "DDP".to_string(),
            GroupSemantics::FEC => "FEC".to_string(),
            GroupSemantics::Other(s) => s.clone(),
        };

        for m in &self.mid_tags {
            s += format!(" {}", m).as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for Group {
    const NAME: &'static str = "group";
}

/// Originator of the session.
///
/// See [RFC 8866 Section 5.2](https://tools.ietf.org/html/rfc8866#section-5.2) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Origin {
    /// User's login on the originating host.
    pub username: Option<String>,
    /// Session ID to make the whole `Origin` unique.
    ///
    /// Must be a numeric string but this is *not* checked.
    pub sess_id: String,
    /// Session version number.
    pub sess_version: u64,
    /// Type of network for this session.
    pub nettype: String,
    /// Type of the `unicast_address`.
    pub addrtype: String,
    /// Address where the session was created.
    pub unicast_address: String,
}

/// Connection data for the session or media.
///
/// See [RFC 8866 Section 5.7](https://tools.ietf.org/html/rfc8866#section-5.7) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Connection {
    /// Type of network for this connection.
    pub nettype: String,
    /// Type of the `connection_address`.
    pub addrtype: String,
    /// Connection address.
    pub connection_address: String,
}

/// Bandwidth information for the session or media.
///
/// See [RFC 8866 Section 5.8](https://tools.ietf.org/html/rfc8866#section-5.8) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bandwidth {
    /// Bandwidth type, usually "CT" or "AS".
    pub bwtype: String,
    /// Bandwidth.
    pub bandwidth: u64,
}

/// Timing information of the session.
///
/// See [RFC 8866 Section 5.9](https://tools.ietf.org/html/rfc8866#section-5.9) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Time {
    /// Start time of the session in seconds since 1900.
    pub start_time: u64,
    /// Stop time of the session in seconds since 1900.
    pub stop_time: u64,
    /// Repeat times.
    pub repeats: Vec<Repeat>,
}

/// Repeat times for timing information.
///
/// See [RFC 8866 Section 5.10](https://tools.ietf.org/html/rfc8866#section-5.10) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Repeat {
    /// Repeat interval in seconds.
    pub repeat_interval: u64,
    /// Duration of one repeat.
    pub active_duration: u64,
    /// Offsets for the repeats from the `start_time`.
    pub offsets: Vec<u64>,
}

/// Time zone information for the session.
///
/// See [RFC 8866 Section 5.11](https://tools.ietf.org/html/rfc8866#section-5.11) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeZone {
    /// Time in seconds since 1900 when the adjustment happens.
    pub adjustment_time: u64,
    /// Amount of the adjustment in seconds.
    pub offset: i64,
}

/// Encryption key for the session or media.
///
/// Note: This field is obsolete and and MUST NOT be used. It is included in only for legacy reasons
/// See [RFC 8866 Section 5.12](https://tools.ietf.org/html/rfc8866#section-5.12) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Key {
    /// Encryption method that is used.
    pub method: String,
    /// Encryption key or information to obtain the encryption key.
    pub encryption_key: Option<String>,
}

/// Attributes for the session or media.
///
/// See [RFC 8866 Section 5.13](https://tools.ietf.org/html/rfc8866#section-5.13) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attribute {
    /// Attribute name.
    pub attribute: String,
    /// Attribute value.
    pub value: Option<String>,
}

/// Media description.
///
/// See [RFC 8866 Section 5.14](https://tools.ietf.org/html/rfc8866#section-5.14) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Media {
    /// Media type, e.g. "audio", "video", "text", "application" or "message".
    pub media: String,
    /// Transport port to which the media is sent.
    pub port: u16,
    /// Number of ports starting at `port` used for the media.
    pub num_ports: Option<u16>,
    /// Transport protocol.
    pub proto: String,
    /// Media format description.
    pub fmt: String,
    /// Media title.
    pub media_title: Option<String>,
    /// Connection data for the media.
    pub connections: Vec<Connection>,
    /// Bandwidth information for the media.
    pub bandwidths: Vec<Bandwidth>,
    /// Encryption key for the media.
    pub key: Option<Key>,
    /// Attributes of the media.
    pub attributes: Vec<Attribute>,
}

/// SDP session description.
///
/// See [RFC 8866 Section 5](https://tools.ietf.org/html/rfc8866#section-5) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Session {
    /// Originator of the session.
    pub origin: Origin,
    /// Name of the session.
    pub session_name: String,
    /// Session description.
    pub session_description: Option<String>,
    /// URI to additional information about the session.
    pub uri: Option<String>,
    /// E-Mail contacts for the session.
    pub emails: Vec<String>,
    /// Phone contacts for the session.
    pub phones: Vec<String>,
    /// Connection data for the session.
    pub connection: Option<Connection>,
    /// Bandwidth information for the session.
    pub bandwidths: Vec<Bandwidth>,
    /// Timing information for the session.
    pub times: Vec<Time>,
    /// Time zone information for the session.
    pub time_zones: Vec<TimeZone>,
    /// Encryption key for the session.
    pub key: Option<Key>,
    /// Attributes of the session.
    pub attributes: Vec<Attribute>,
    /// Media descriptions for this session.
    pub medias: Vec<Media>,
}

/// Error returned when an attribute is not found.
#[derive(Debug, PartialEq, Eq)]
pub struct AttributeNotFoundError;

impl std::error::Error for AttributeNotFoundError {}

impl std::fmt::Display for AttributeNotFoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Attribute not found")
    }
}

/// Attribute error with specific details
// TODO: combine this and AttributeNotFoundError?
#[derive(Debug, PartialEq, Eq)]
pub struct AttributeErr(&'static str);

impl std::error::Error for AttributeErr {}

impl std::fmt::Display for AttributeErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Media {
    /// Checks if the given attribute exists.
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.attribute == name)
    }

    /// Gets the first value of the given attribute, if existing.
    pub fn get_first_attribute_value(
        &self,
        name: &str,
    ) -> Result<Option<&str>, AttributeNotFoundError> {
        self.attributes
            .iter()
            .find(|a| a.attribute == name)
            .ok_or(AttributeNotFoundError)
            .map(|a| a.value.as_deref())
    }

    /// Gets an iterator over all attribute values of the given name, if existing.
    pub fn get_attribute_values<'a>(
        &'a self,
        name: &'a str,
    ) -> Result<impl Iterator<Item = Option<&'a str>> + 'a, AttributeNotFoundError> {
        let mut iter = self
            .attributes
            .iter()
            .filter(move |a| a.attribute == name)
            .map(|a| a.value.as_deref())
            .peekable();
        if iter.peek().is_some() {
            Ok(iter)
        } else {
            Err(AttributeNotFoundError)
        }
    }

    /// Tries to parse the `media` `String` of `self` as `MediaType`
    pub fn try_parse_mediatype(&self) -> Result<MediaType, ParseEnumError> {
        MediaType::from_str(self.media.as_str())
    }

    /// Sets the `media` `String` of `self` from the specified `MediaType`
    pub fn set_from_mediatype(&mut self, media: MediaType) {
        self.media = media.to_string();
    }

    /// Tries to parse the `proto` `String` of `self` as `TransportProto`
    pub fn try_parse_transport_proto(&self) -> Result<TransportProto, ParseEnumError> {
        TransportProto::from_str(self.proto.as_str())
    }

    /// Sets the `proto` `String` of `self` from the specified `TransportProto`
    pub fn set_from_transport_proto(&mut self, proto: TransportProto) {
        self.proto = proto.to_string();
    }
    /// Constructs a `MediaType` from a string
    pub fn try_mediatype(&self) -> Result<MediaType, ParseEnumError> {
        MediaType::from_str(self.media.as_str())
    }

    /// Gets an iterator over all attribute values of the given name.
    ///
    /// Each item is a `Result` with the inferred type in `Ok` and `AttributeErr` in `Err`.
    ///
    /// The iterator does not terminate upon an error item; continues with the next attribute
    pub fn attributes_typed<'a, T: TypedAttribute>(
        &'a self,
    ) -> impl Iterator<Item = Result<T, AttributeErr>> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.attribute.eq_ignore_ascii_case(T::NAME))
            .map(|a| {
                let Some(s) = &a.value else {
                    // does not have a value for the attribute
                    return Err(AttributeErr("No value for the attribute"));
                };

                T::from_str(s)
            })
    }
}

impl Session {
    /// Checks if the given attribute exists.
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.attribute == name)
    }

    /// Gets the first value of the given attribute, if existing.
    pub fn get_first_attribute_value(
        &self,
        name: &str,
    ) -> Result<Option<&str>, AttributeNotFoundError> {
        self.attributes
            .iter()
            .find(|a| a.attribute == name)
            .ok_or(AttributeNotFoundError)
            .map(|a| a.value.as_deref())
    }

    /// Gets an iterator over all attribute values of the given name, if existing.
    pub fn get_attribute_values<'a>(
        &'a self,
        name: &'a str,
    ) -> Result<impl Iterator<Item = Option<&'a str>> + 'a, AttributeNotFoundError> {
        let mut iter = self
            .attributes
            .iter()
            .filter(move |a| a.attribute == name)
            .map(|a| a.value.as_deref())
            .peekable();
        if iter.peek().is_some() {
            Ok(iter)
        } else {
            Err(AttributeNotFoundError)
        }
    }

    /// Gets an iterator over all attribute values of the given name.
    ///
    /// Each item is a `Result` with the inferred type in `Ok` and `AttributeErr` in `Err`.
    ///
    /// The iterator does not terminate upon an error item; continues with the next attribute
    pub fn attributes_typed<'a, T: TypedAttribute>(
        &'a self,
    ) -> impl Iterator<Item = Result<T, AttributeErr>> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.attribute.eq_ignore_ascii_case(T::NAME))
            .map(|a| {
                let Some(s) = &a.value else {
                    // does not have a value for the attribute
                    return Err(AttributeErr("No value for the attribute"));
                };

                T::from_str(s)
            })
    }
}

impl Origin {
    /// Tries to parse the `addrtype` `String` of `self` as `AddrType`
    pub fn try_parse_addrtype(&self) -> Result<AddrType, ParseEnumError> {
        AddrType::from_str(self.addrtype.as_str())
    }

    /// Sets the `addrtype` `String` of `self` from the specified `AddrType`
    pub fn set_from_addrtype(&mut self, addrtype: AddrType) {
        self.addrtype = addrtype.to_string();
    }

    /// Tries to parse the `nettype` `String` of `self` as `NetType`
    pub fn try_parse_nettype(&self) -> Result<NetType, ParseEnumError> {
        NetType::from_str(self.nettype.as_str())
    }

    /// Sets the `nettype` `String` of `self` from the specified `NetType`
    pub fn set_from_nettype(&mut self, nettype: NetType) {
        self.nettype = nettype.to_string();
    }

    /// Tries to parse the `unicast_address` `String` of `self` as `IpAddr`
    pub fn try_parse_unicast_address(&self) -> Result<IpAddr, AddrParseError> {
        self.unicast_address.parse()
    }

    /// Sets the `unicast_address` `String` of `self` from the specified `IpAddr`
    pub fn set_unicast_address(&mut self, unicast_address: IpAddr) {
        self.unicast_address = unicast_address.to_string();
    }
}

impl Connection {
    /// Tries to parse the `addrtype` `String` of `self` as `AddrType`
    pub fn try_parse_addrtype(&self) -> Result<AddrType, ParseEnumError> {
        AddrType::from_str(self.addrtype.as_str())
    }

    /// Sets the `addrtype` `String` of `self` from the specified `AddrType`
    pub fn set_from_addrtype(&mut self, addrtype: AddrType) {
        self.addrtype = addrtype.to_string();
    }

    /// Tries to parse the `nettype` `String` of `self` as `NetType`
    pub fn try_parse_nettype(&self) -> Result<NetType, ParseEnumError> {
        NetType::from_str(self.nettype.as_str())
    }

    /// Sets the `nettype` `String` of `self` from the specified `NetType`
    pub fn set_from_nettype(&mut self, nettype: NetType) {
        self.nettype = nettype.to_string();
    }

    /// Tries to parse the `connection_address` `String` of `self` as `IpAddr`
    pub fn try_parse_connection_address(&self) -> Result<IpAddr, AddrParseError> {
        self.connection_address.parse()
    }

    /// Sets the `connection_address` `String` of `self` from the specified `IpAddr`
    pub fn set_connection_address(&mut self, connection_address: IpAddr) {
        self.connection_address = connection_address.to_string();
    }
}

impl Bandwidth {
    /// Tries to parse the `bwtype` `String` of `self` as `BandwidthType`
    pub fn try_parse_bwtype(&self) -> Result<BandwidthType, ParseEnumError> {
        BandwidthType::from_str(self.bwtype.as_str())
    }

    /// Sets the `bwtype` `String` of `self` from the specified `BandwidthType`
    pub fn set_from_bwtype(&mut self, bwtype: BandwidthType) {
        self.bwtype = bwtype.to_string();
    }
}

impl Key {
    /// Tries to parse the `method` `String` of `self` as `KeyMethod`
    pub fn try_parse_keymethod(&self) -> Result<KeyMethod, ParseEnumError> {
        KeyMethod::from_str(self.method.as_str())
    }

    /// Sets the `method` `String` of `self` from the specified `KeyMethod`
    pub fn set_from_keymethod(&mut self, method: KeyMethod) {
        self.method = method.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_write() {
        let sdp = "v=0\r
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r
s=SDP Seminar\r
i=A Seminar on the session description protocol\r
u=http://www.example.com/seminars/sdp.pdf\r
e=j.doe@example.com (Jane Doe)\r
p=+1 617 555-6011\r
c=IN IP4 224.2.17.12/127\r
b=AS:128\r
t=2873397496 2873404696\r
r=7d 1h 0 25h\r
z=2882844526 -1h 2898848070 0\r
k=clear:1234\r
a=recvonly\r
m=audio 49170 RTP/AVP 0\r
a=fmtp:0 0-15\r
m=video 51372/2 RTP/AVP 99 97 98\r
a=rtpmap:99 h263-1998/90000\r
a=fingerprint:sha-256 3A:96:6D:57:B2:C2:C7:61:A0:46:3E:1C:97:39:D3:F7:0A:88:A0:B1:EC:03:FB:10:A5:5D:3A:37:AB:DD:02:AA\r
a=extmap:2/sendrecv http://example.com/082005/ext.htm#xmeta short\r
";
        let parsed = Session::parse(sdp.as_bytes()).unwrap();
        let mut written = vec![];
        parsed.write(&mut written).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), sdp);
        assert_eq!(parsed.origin.try_parse_addrtype(), Ok(AddrType::Ip4));
        assert_ne!(parsed.origin.try_parse_nettype(), Ok(NetType::Pstn));
        assert_eq!(
            parsed.origin.try_parse_unicast_address(),
            Ok(IpAddr::V4(std::net::Ipv4Addr::new(10, 47, 16, 5)))
        );
        assert_eq!(parsed.medias[0].try_parse_mediatype(), Ok(MediaType::Audio));
        assert_ne!(
            parsed.medias[1].try_parse_transport_proto(),
            Ok(TransportProto::RtpSavpf)
        );
        let f = fallible_iterator::convert(parsed.medias[0].attributes_typed::<Fmtp>())
            .collect::<Vec<_>>()
            .expect("Valid vector of attributes");
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].clone().format_specific_params[0].param,
            "0-15"
        );

        let e = fallible_iterator::convert(parsed.medias[1].attributes_typed::<ExtMap>())
            .collect::<Vec<_>>()
            .expect("Vector of extmap attributes");
        assert_eq!(e[0].id, 2);
        assert_eq!(e[0].direction, Some(Direction::SendRecv));
        assert_eq!(
            e[0].uri,
            "http://example.com/082005/ext.htm#xmeta".to_string()
        );
        assert_eq!(e[0].attributes, Some("short".to_string()));

        let f = fallible_iterator::convert(parsed.medias[1].attributes_typed::<Fingerprint>())
            .collect::<Vec<_>>()
            .expect("Vector of fingerprint attributes");

        assert_eq!(f[0].hash_func, HashFunc::SHA256);
        assert_eq!(f[0].fingerprint[4], 0xB2);
        assert_eq!(f[0].fingerprint.last(), Some(&0xAA));
    }

    #[test]
    fn parse_media_attributes() {
        let media = Media {
            media: "video".into(),
            port: 51372,
            num_ports: Some(2),
            proto: "RTP/AVP".into(),
            fmt: "99 100".into(),
            media_title: None,
            connections: vec![],
            bandwidths: vec![],
            key: None,
            attributes: vec![
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some("99 h263-1998/90000".into()),
                },
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some("100 h264/90000".into()),
                },
                Attribute {
                    attribute: "rtpmap".into(),
                    value: None,
                },
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some(
                        RtpMap {
                            payload_type: 101,
                            encoding_name: "L16".into(),
                            clock_rate: 16000,
                            encoding_params: Some("2".into()),
                        }
                        .to_string(),
                    ),
                },
                Attribute {
                    attribute: "fmtp".into(),
                    value: Some(
                        Fmtp {
                            fmt: 100,
                            format_specific_params: Vec::from([
                                FmtpParam {
                                    param: "profile-level-id".to_string(),
                                    val: Some("42e016".to_string()),
                                },
                                FmtpParam {
                                    param: "max-mbps".to_string(),
                                    val: Some("108000".to_string()),
                                },
                                FmtpParam {
                                    param: "max-fs".to_string(),
                                    val: Some("3600".to_string()),
                                },
                            ]),
                        }
                        .to_string(),
                    ),
                },
                Attribute {
                    attribute: "rtcp".into(),
                    value: Some(
                        Rtcp {
                            port: 53020,
                            nettype: NetType::In,
                            addrtype: AddrType::Ip4,
                            connection_address: IpAddr::V4(std::net::Ipv4Addr::new(126, 16, 64, 4)),
                        }
                        .to_string(),
                    ),
                },
                Attribute {
                    attribute: "fingerprint".into(),
                    value: Some(
                        Fingerprint {
                            hash_func: HashFunc::Other(("custom").to_string()),
                            fingerprint: [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6].to_vec(),
                        }
                        .to_string(),
                    ),
                },
            ],
        };

        assert!(media.has_attribute("rtpmap"));
        assert!(media.has_attribute("rtcp"));
        assert!(!media.has_attribute("foo"));

        assert_eq!(
            media.get_first_attribute_value("rtpmap"),
            Ok(Some("99 h263-1998/90000"))
        );
        assert_eq!(
            media.get_first_attribute_value("rtcp"),
            Ok(Some("53020 IN IP4 126.16.64.4"))
        );
        assert_eq!(
            media.get_first_attribute_value("foo"),
            Err(AttributeNotFoundError)
        );

        assert_eq!(
            media
                .get_attribute_values("rtpmap")
                .unwrap()
                .collect::<Vec<_>>(),
            &[
                Some("99 h263-1998/90000"),
                Some("100 h264/90000"),
                None,
                Some("101 L16/16000/2"),
            ]
        );

        let v = media
            .attributes_typed::<RtpMap>()
            .collect::<Vec<Result<RtpMap, AttributeErr>>>();
        assert_eq!(v[0].as_ref().unwrap().clock_rate, 90000);
        assert_eq!(v[1].as_ref().unwrap().encoding_name, "h264");
        assert_eq!(v[2], Err(AttributeErr("No value for the attribute")));
        assert_eq!(
            v[3].as_ref().unwrap().encoding_params.as_ref().unwrap(),
            "2"
        );

        let v = media
            .attributes_typed::<RtpMap>()
            .filter(|attr| {
                let Ok(at) = attr else { return false };
                at.payload_type == 99
            })
            .collect::<Vec<_>>();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].as_ref().unwrap().encoding_name, "h263-1998");

        assert_eq!(
            media.get_first_attribute_value("fmtp"),
            Ok(Some(
                "100 profile-level-id=42e016;max-mbps=108000;max-fs=3600"
            ))
        );

        let r = media.attributes_typed::<Rtcp>().collect::<Vec<_>>();
        assert_eq!(r[0].as_ref().unwrap().addrtype, AddrType::Ip4);
        assert_eq!(r[0].as_ref().unwrap().port, 53020);

        assert_eq!(
            media
                .get_attribute_values("fingerprint")
                .unwrap()
                .collect::<Vec<_>>(),
            &[Some("custom A1:B2:C3:D4:E5:F6")]
        );

        assert!(media.get_attribute_values("foo").is_err());
    }

    #[test]
    fn parse_session_attributes() {
        let session = Session {
            origin: Origin {
                username: Some("jdoe".into()),
                sess_id: "2890844526".into(),
                sess_version: 2890842807,
                nettype: "IN".into(),
                addrtype: "IP4".into(),
                unicast_address: "10.47.16.5".into(),
            },
            session_name: "SDP Seminar".into(),
            session_description: None,
            uri: None,
            emails: vec![],
            phones: vec![],
            connection: None,
            bandwidths: vec![],
            times: vec![Time {
                start_time: 0,
                stop_time: 0,
                repeats: vec![],
            }],
            time_zones: vec![],
            key: None,
            attributes: vec![
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some("99 h263-1998/90000".into()),
                },
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some("100 h264/90000".into()),
                },
                Attribute {
                    attribute: "rtpmap".into(),
                    value: Some(
                        RtpMap {
                            payload_type: 101,
                            encoding_name: "L16".into(),
                            clock_rate: 16000,
                            encoding_params: Some("2".into()),
                        }
                        .to_string(),
                    ),
                },
                Attribute {
                    attribute: "rtcp".into(),
                    value: None,
                },
                Attribute {
                    attribute: "extmap".into(),
                    value: Some(
                        ExtMap {
                            id: 1,
                            direction: None,
                            uri: "URI-toffset".to_string(),
                            attributes: None,
                        }
                        .to_string(),
                    ),
                },
            ],
            medias: vec![],
        };

        assert!(session.has_attribute("rtpmap"));
        assert!(session.has_attribute("rtcp"));
        assert!(!session.has_attribute("foo"));

        assert_eq!(
            session.get_first_attribute_value("rtpmap"),
            Ok(Some("99 h263-1998/90000"))
        );

        let v = session
            .get_first_attribute_value("rtpmap")
            .unwrap()
            .unwrap();
        let rtpmap = RtpMap::from_str(v).unwrap();
        assert_eq!(rtpmap.clock_rate, 90000);
        assert_eq!(rtpmap.encoding_name, "h263-1998");
        assert_ne!(rtpmap.encoding_name, "h263");
        assert_ne!(rtpmap.encoding_params, Some("2".to_string()));
        assert_eq!(rtpmap.payload_type, 99);

        assert_eq!(session.get_first_attribute_value("rtcp"), Ok(None));
        assert_eq!(
            session.get_first_attribute_value("foo"),
            Err(AttributeNotFoundError)
        );

        assert_eq!(
            session
                .get_attribute_values("rtpmap")
                .unwrap()
                .collect::<Vec<_>>(),
            &[
                Some("99 h263-1998/90000"),
                Some("100 h264/90000"),
                Some("101 L16/16000/2")
            ]
        );
        assert_eq!(
            session
                .get_attribute_values("rtcp")
                .unwrap()
                .collect::<Vec<_>>(),
            &[None]
        );

        assert_eq!(
            session
                .get_attribute_values("extmap")
                .unwrap()
                .collect::<Vec<_>>(),
            &[Some("1 URI-toffset")]
        );

        assert!(session.get_attribute_values("foo").is_err());

        let a = fallible_iterator::convert(session.attributes_typed::<RtpMap>())
            .collect::<Vec<_>>()
            .expect("Valid vector of attributes");
        assert_eq!(a[2].encoding_name, "L16");
        assert_eq!(a[0].payload_type, 99);
    }

    #[test]
    fn parse_rtcp_fb() {
        let sdp = "v=0\r
o=alice 3203093520 3203093520 IN IP4 host.example.com\r
s=Multicast video with feedback\r
t=3203130148 3203137348\r
m=audio 49170 RTP/AVP 0\r
c=IN IP4 224.2.1.183\r
a=rtpmap:0 PCMU/8000\r
m=video 51372 RTP/AVPF 98 99\r
c=IN IP4 224.2.1.184\r
a=rtpmap:98 H263-1998/90000\r
a=rtpmap:99 H261/90000\r
a=rtcp-fb:* nack\r
a=rtcp-fb:98 nack rpsi\r
a=rtcp-fb:* trr-int 1000\r
a=rtcp-fb:98 ccm vbcm 1 2\r
a=rtcp-fb:* ccm tmmbr smaxpr=120\r
";

        let parsed = Session::parse(sdp.as_bytes()).unwrap();
        let mut written = vec![];
        parsed.write(&mut written).unwrap();

        let v = fallible_iterator::convert(parsed.medias[1].attributes_typed::<RtcpFb>())
            .collect::<Vec<_>>()
            .expect("Valid vector of attributes");
        assert_eq!(v[0].pt, RtcpFbPt::Wildcard);
        assert_eq!(v[1].val, RtcpFbVal::Nack(Some(RtcpFbNack::Rpsi)));
        assert_eq!(v[2].val, RtcpFbVal::TrrInt(1000));
        assert_eq!(v[3].val, RtcpFbVal::Ccm(RtcpFbCcm::Vbcm(vec![1, 2])));
        assert_eq!(
            v[4].val,
            RtcpFbVal::Ccm(RtcpFbCcm::Tmmbr(Some("smaxpr=120".to_string())))
        );
    }

    #[test]
    fn parse_group_attribute() {
        let sdp = "v=0\r
o=Laura 289083124 289083124 IN IP4 two.example.com\r
c=IN IP4 233.252.0.1/127\r
t=0 0\r
a=group:LS 1 2\r
m=audio 30000 RTP/AVP 0\r
a=mid:1\r
m=video 30002 RTP/AVP 31\r
a=mid:2\r
m=audio 30004 RTP/AVP 0\r
i=This media stream contains the Spanish translation\r
a=mid:3\r
";
        let parsed = Session::parse(sdp.as_bytes()).unwrap();

        let g = parsed.attributes_typed::<Group>().collect::<Vec<_>>();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].as_ref().unwrap().semantics, GroupSemantics::LS);
        assert_eq!(
            g[0].as_ref().unwrap().mid_tags,
            vec!["1".to_string(), "2".to_string()]
        );
    }
}
