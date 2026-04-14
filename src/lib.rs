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
//! // returns an iterator of type `Iterator<Item = Result<RtpMap, AttributeError>>`
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
pub trait TypedAttribute: Display + FromStr<Err = AttributeError> {
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((pt, rest)) = s.split_once(' ') else {
            return Err(AttributeError::UnsupportedFormat {
                val: s.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(pt) = pt.parse::<u8>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Payload type".to_string(),
                val: pt.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        if pt > 127 {
            return Err(AttributeError::InvalidParamValue {
                param: "Payload type".to_string(),
                val: format!("{pt}(expected 0-127)"),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        }

        let mut i = rest.splitn(3, '/');
        let Some(encoding) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Encoding name".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(clock_rate) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Clock rate".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(clock_rate) = clock_rate.parse::<u32>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Clock rate".to_string(),
                val: clock_rate.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((fmt, rest)) = s.split_once(' ') else {
            return Err(AttributeError::UnsupportedFormat {
                val: s.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(fmt) = fmt.parse::<u8>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "fmtp".to_string(),
                val: fmt.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');
        let Some(port) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Port".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(port) = port.parse::<u16>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Port".to_string(),
                val: port.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(nettype) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Network type".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(nettype) = NetType::from_str(nettype) else {
            return Err(AttributeError::InvalidParamValue {
                param: "Network type".to_string(),
                val: nettype.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(addrtype) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Address type".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(addrtype) = AddrType::from_str(addrtype) else {
            return Err(AttributeError::InvalidParamValue {
                param: "Address type".to_string(),
                val: addrtype.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(connection_addr) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Connection address".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(connection_address) = connection_addr.parse() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Connection address".to_string(),
                val: connection_addr.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        if let Some(unexpected) = i.next() {
            return Err(AttributeError::UnexpectedTrailingItem {
                val: unexpected.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        }

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

#[derive(Debug, PartialEq, Clone)]
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');
        let Some(pt) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Payload format".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let pt = if let Ok(pt) = pt.parse::<u8>() {
            RtcpFbPt::Fmt(pt)
        } else if pt == "*" {
            RtcpFbPt::Wildcard
        } else {
            return Err(AttributeError::InvalidParamValue {
                param: "Payload format".to_string(),
                val: pt.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(val) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Rtcp feedback value".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
                            if let RtcpFbPt::Fmt(pt) = pt {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "Payload type".to_string(),
                                    val: format!("{pt}(expected wildcard (*))"),
                                    attr: <Self as TypedAttribute>::NAME.to_string(),
                                });
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
                        return Err(AttributeError::InvalidParamValue {
                            param: "trr-int".to_string(),
                            val: val.to_string(),
                            attr: <Self as TypedAttribute>::NAME.to_string(),
                        });
                    };
                    RtcpFbVal::TrrInt(i)
                } else {
                    return Err(AttributeError::Other {
                        error: "No trr-int value".to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
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
                                    return Err(AttributeError::InvalidParamValue {
                                        param: "vbcm".to_string(),
                                        val: vbcm_val.to_string(),
                                        attr: <Self as TypedAttribute>::NAME.to_string(),
                                    });
                                };
                                v.push(p);
                            }
                            RtcpFbCcm::Vbcm(v)
                        }
                        other => RtcpFbCcm::Other(other.to_string()),
                    };
                    RtcpFbVal::Ccm(ccm_val)
                } else {
                    return Err(AttributeError::ParamNotFound {
                        param: "Ccm param".to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.splitn(3, ' ');

        let Some(id_direction) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "id/direction".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let mut d = id_direction.split('/');

        let Some(id) = d.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "id".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let direction = if let Some(d) = d.next() {
            let Ok(dir) = Direction::from_str(d) else {
                return Err(AttributeError::InvalidParamValue {
                    param: "Direction".to_string(),
                    val: d.to_string(),
                    attr: <Self as TypedAttribute>::NAME.to_string(),
                });
            };
            Some(dir)
        } else {
            None
        };

        let Ok(id) = id.parse::<u8>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Id".to_string(),
                val: id.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(uri) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "URI".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
    type Err = AttributeError;

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
            return Err(AttributeError::ParamNotFound {
                param: "Hash function".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let mut fingerprint: Vec<u8> = vec![];
        if let Some(fp) = i.next() {
            for f in fp.split(':') {
                let Ok(mut f) = hex::decode(f) else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "Hash function".to_string(),
                        val: f.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                fingerprint.append(&mut f);
            }
        } else {
            return Err(AttributeError::ParamNotFound {
                param: "Hash value".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');

        let Some(semantics) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Semantics".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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
            return Err(AttributeError::ParamNotFound {
                param: "Media identification tags".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
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

/// Setup attribute for the session or media.
///
/// See [RFC 4145 Section 4](https://tools.ietf.org/html/rfc4145#section-4) for more details.
#[derive(Debug, Clone, PartialEq)]
pub enum Setup {
    /// Initiator of the connection.
    Active,
    /// Acceptor of the connection.
    Passive,
    /// Act as either initiator or acceptor of the connection.
    ActPass,
    /// Do not establish a connection.
    HoldConn,
}

impl FromStr for Setup {
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if "active".eq_ignore_ascii_case(s) {
            Ok(Setup::Active)
        } else if "passive".eq_ignore_ascii_case(s) {
            Ok(Setup::Passive)
        } else if "actpass".eq_ignore_ascii_case(s) {
            Ok(Setup::ActPass)
        } else if "holdconn".eq_ignore_ascii_case(s) {
            Ok(Setup::HoldConn)
        } else {
            Err(AttributeError::Other {
                error: format!("Invalid Setup value {s}"),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            })
        }
    }
}

impl Display for Setup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Setup::Active => "active",
            Setup::Passive => "passive",
            Setup::ActPass => "actpass",
            Setup::HoldConn => "holdconn",
        };
        f.write_str(s)
    }
}

impl TypedAttribute for Setup {
    const NAME: &'static str = "setup";
}

/// Source attribute types.
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

/// SSRC media attribute.
///
/// See [RFC 5576 Section 4.1](https://tools.ietf.org/html/rfc5576#section-4.1)
#[derive(Debug, Clone, PartialEq)]
pub struct Ssrc {
    pub ssrc_id: u32,
    pub attribute: SsrcAttribute,
    pub value: Option<String>,
}

impl FromStr for Ssrc {
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((ssrc_id_str, rest)) = s.split_once(' ') else {
            return Err(AttributeError::ParamNotFound {
                param: "Ssrc id".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(ssrc_id) = ssrc_id_str.parse::<u32>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Ssrc id".to_string(),
                val: ssrc_id_str.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let (attr, value) = if let Some((attr_str, value)) = rest.split_once(':') {
            (attr_str, Some(value.to_string()))
        } else {
            (rest, None)
        };

        let attribute = if "cname".eq_ignore_ascii_case(attr) {
            SsrcAttribute::Cname
        } else if "previous-ssrc".eq_ignore_ascii_case(attr) {
            SsrcAttribute::PreviousSsrc
        } else if "fmtp".eq_ignore_ascii_case(attr) {
            SsrcAttribute::Fmtp
        } else {
            SsrcAttribute::Other(attr.to_string())
        };

        Ok(Self {
            ssrc_id,
            attribute,
            value,
        })
    }
}

impl Display for Ssrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = self.ssrc_id.to_string();
        let attr_str = match &self.attribute {
            SsrcAttribute::Cname => "cname",
            SsrcAttribute::PreviousSsrc => "previous-ssrc",
            SsrcAttribute::Fmtp => "fmtp",
            SsrcAttribute::Other(other) => other.as_str(),
        };

        s += format!(" {}", attr_str).as_str();

        if let Some(value) = &self.value {
            s += format!(":{}", value).as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for Ssrc {
    const NAME: &'static str = "ssrc";
}

/// SSRC group attribute
///
/// See [RFC 5576 Section 4.2](https://tools.ietf.org/html/rfc5576#section-4.2)
#[derive(Debug, PartialEq, Clone)]
pub struct SsrcGroup {
    pub semantics: GroupSemantics,
    pub ssrc_ids: Vec<u32>,
}

impl FromStr for SsrcGroup {
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');

        let Some(semantics) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Semantics".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let semantics = if "FEC".eq_ignore_ascii_case(semantics) {
            GroupSemantics::FEC
        } else if "FID".eq_ignore_ascii_case(semantics) {
            GroupSemantics::FID
        } else {
            // The initial defined semantics for ssrc-group attribute are FID and FEC
            // The other registered group semantics are not useful for source grouping
            // But keep this open for any other new semantics that are not part of GroupSemantics
            GroupSemantics::Other(semantics.to_string())
        };

        let mut ssrc_ids = vec![];
        for ssrc_id in i {
            let Ok(ssrc_id) = ssrc_id.parse::<u32>() else {
                return Err(AttributeError::InvalidParamValue {
                    param: "Ssrc id".to_string(),
                    val: ssrc_id.to_string(),
                    attr: <Self as TypedAttribute>::NAME.to_string(),
                });
            };
            ssrc_ids.push(ssrc_id);
        }

        Ok(Self {
            semantics,
            ssrc_ids,
        })
    }
}

impl Display for SsrcGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = match &self.semantics {
            GroupSemantics::FEC => "FEC".to_string(),
            GroupSemantics::FID => "FID".to_string(),
            // Semantics other than FEC and FID are not useful for source grouping but still displaying
            // them for debugging purpose
            GroupSemantics::LS => "LS".to_string(),
            GroupSemantics::SRF => "SRF".to_string(),
            GroupSemantics::ANAT => "ANAT".to_string(),
            GroupSemantics::DDP => "DDP".to_string(),
            GroupSemantics::Other(s) => s.clone(),
        };

        for ssrc_id in &self.ssrc_ids {
            s += format!(" {}", ssrc_id).as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for SsrcGroup {
    const NAME: &'static str = "ssrc-group";
}

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

#[derive(Debug, PartialEq, Clone)]
/// SRTP Key parameter
///
/// See [RFC 4568 Section 6.1](https://datatracker.ietf.org/doc/html/rfc4568#section-6.1)
pub struct SrtpKeyParam {
    /// Concatenated key and salt, base64 encoded
    pub key_and_salt: String,
    /// Master key lifetime (max number of SRTP or SRTCP packets using this master key)
    pub lifetime: Option<u32>,
    /// MKI (Master Key Identifier) and length of the MKI field in SRTP packets
    pub mki_and_length: Option<(u32, u32)>,
}

impl FromStr for SrtpKeyParam {
    type Err = AttributeError;
    fn from_str(key_param: &str) -> Result<Self, Self::Err> {
        let mut k = key_param.split('|');

        let Some(key_and_salt_with_method) = k.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Srtp Key and Salt".to_string(),
                attr: Crypto::NAME.to_string(),
            });
        };

        let key_and_salt = if key_and_salt_with_method.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("inline:")) {
            &key_and_salt_with_method[7..]
        } else {
            return Err(AttributeError::InvalidParamValue {
                param: "Strp Key and Salt".to_string(),
                val: key_and_salt_with_method.to_string(),
                attr: Crypto::NAME.to_string(),
            });
        };

        let (lifetime, mki_and_length) = if let Some(next_param) = k.next() {
            match next_param.split_once(':') {
                Some(mki_and_length) => {
                    // lifetime is not specified, but only MKI and its length
                    let Ok(mki) = mki_and_length.0.parse::<u32>() else {
                        return Err(AttributeError::InvalidParamValue {
                            param: "MKI".to_string(),
                            val: next_param.to_string(),
                            attr: Crypto::NAME.to_string(),
                        });
                    };

                    let Ok(len) = mki_and_length.1.parse::<u32>() else {
                        return Err(AttributeError::InvalidParamValue {
                            param: "Length".to_string(),
                            val: next_param.to_string(),
                            attr: Crypto::NAME.to_string(),
                        });
                    };
                    (None, Some((mki, len)))
                }
                None => {
                    // lifetime is specified
                    let lifetime = match next_param.strip_prefix("2^") {
                        Some(exp) => {
                            let Ok(exp) = exp.parse::<u32>() else {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "Lifetime".to_string(),
                                    val: next_param.to_string(),
                                    attr: Crypto::NAME.to_string(),
                                });
                            };
                            // 2u32.pow(exp) panics for exp >= 32
                            if exp >= 32 {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "Lifetime".to_string(),
                                    val: format!("{exp}(expected 0-32)"),
                                    attr: Crypto::NAME.to_string(),
                                });
                            }
                            Some(2u32.pow(exp))
                        }
                        None => {
                            let Ok(lifetime) = next_param.parse::<u32>() else {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "Lifetime".to_string(),
                                    val: next_param.to_string(),
                                    attr: Crypto::NAME.to_string(),
                                });
                            };
                            Some(lifetime)
                        }
                    };

                    // now parse the MKI and length
                    let mki_and_length = if let Some(m) = k.next() {
                        if let Some(p) = m.split_once(':') {
                            let Ok(mki) = p.0.parse::<u32>() else {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "MKI".to_string(),
                                    val: m.to_string(),
                                    attr: Crypto::NAME.to_string(),
                                });
                            };

                            let Ok(len) = p.1.parse::<u32>() else {
                                return Err(AttributeError::InvalidParamValue {
                                    param: "Length".to_string(),
                                    val: m.to_string(),
                                    attr: Crypto::NAME.to_string(),
                                });
                            };
                            Some((mki, len))
                        } else {
                            return Err(AttributeError::ParamNotFound {
                                param: "MKI and Length".to_string(),
                                attr: Crypto::NAME.to_string(),
                            });
                        }
                    } else {
                        None
                    };

                    (lifetime, mki_and_length)
                }
            }
        } else {
            (None, None)
        };

        if let Some((_, len)) = mki_and_length {
            if !(1..=128).contains(&len) {
                return Err(AttributeError::InvalidParamValue {
                    param: "MKI length".to_string(),
                    val: len.to_string(),
                    attr: Crypto::NAME.to_string(),
                });
            }
        }

        if let Some(unexpected) = k.next() {
            return Err(AttributeError::UnexpectedTrailingItem {
                val: unexpected.to_string(),
                attr: Crypto::NAME.to_string(),
            });
        }

        Ok(Self {
            key_and_salt: key_and_salt.to_string(),
            lifetime,
            mki_and_length,
        })
    }
}

impl Display for SrtpKeyParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("inline:{}", self.key_and_salt);
        if let Some(lifetime) = self.lifetime {
            if lifetime.is_power_of_two() {
                s += format!("|2^{}", lifetime.trailing_zeros()).as_str();
            } else {
                s += format!("|{}", lifetime).as_str();
            }
        }

        if let Some((mki, length)) = self.mki_and_length {
            s += format!("|{}:{}", mki, length).as_str()
        }
        f.write_str(&s)
    }
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

/// Cryptographic information for the media
///
/// See [RFC 4568 Section 3](https://tools.ietf.org/html/rfc4568#section-4)
#[derive(Debug, PartialEq, Clone)]
pub struct Crypto {
    pub tag: u32,
    pub crypto_suite: CryptoSuite,
    pub key_params: Vec<SrtpKeyParam>,
    pub session_params: Vec<SrtpSessionParam>,
}

impl FromStr for Crypto {
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');

        let Some(tag) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Tag".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(tag) = tag.parse::<u32>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Tag".to_string(),
                val: tag.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(crypto_suite) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "CryptoSuite".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let crypto_suite = if "AES_CM_128_HMAC_SHA1_32".eq_ignore_ascii_case(crypto_suite) {
            CryptoSuite::AesCm128HmacSha1_32
        } else if "F8_128_HMAC_SHA1_80".eq_ignore_ascii_case(crypto_suite) {
            CryptoSuite::F8_128HmacSha1_80
        } else if "AES_CM_128_HMAC_SHA1_80".eq_ignore_ascii_case(crypto_suite) {
            CryptoSuite::AesCm128HmacSha1_80
        } else {
            CryptoSuite::Other(crypto_suite.to_string())
        };

        let Some(key_params_str) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Key params".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let mut key_params: Vec<SrtpKeyParam> = Vec::new();

        for key_param in key_params_str.split(';') {
            let key_param = SrtpKeyParam::from_str(key_param)?;
            key_params.push(key_param);
        }

        let mut session_params: Vec<SrtpSessionParam> = Vec::new();
        for s in &mut i {
            let s = s.to_ascii_uppercase();
            let param = if let Some(kdr_val) = s.strip_prefix("KDR=") {
                let Ok(kdr_val) = kdr_val.parse::<u8>() else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "KDR".to_string(),
                        val: kdr_val.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                // Note: the range for KDR value is conflicting in the spec,
                // rfc4568#section-6.3.1 says the range should be 1,2,...24 and
                // the grammar in rfc4568#section-9.2 says it should be 0..24.
                // So using the bigger range i.e., 0..24 for now
                if !(0..=24).contains(&kdr_val) {
                    return Err(AttributeError::InvalidParamValue {
                        param: "KDR".to_string(),
                        val: format!("{kdr_val}(expected range 0..24)"),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                }
                SrtpSessionParam::Kdr(kdr_val)
            } else if s == "UNENCRYPTED_SRTCP" {
                SrtpSessionParam::UnencryptedSrtcp
            } else if s == "UNENCRYPTED_SRTP" {
                SrtpSessionParam::UnencryptedSrtp
            } else if s == "UNAUTHENTICATED_SRTP" {
                SrtpSessionParam::UnauthenticatedSrtp
            } else if let Some(fec_ord) = s.strip_prefix("FEC_ORDER=") {
                if fec_ord.eq_ignore_ascii_case("FEC_SRTP") {
                    SrtpSessionParam::FecOrder(FecOrder::FecSrtp)
                } else if fec_ord.eq_ignore_ascii_case("SRTP_FEC") {
                    SrtpSessionParam::FecOrder(FecOrder::SrtpFec)
                } else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "FEC order".to_string(),
                        val: s.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                }
            } else if let Some(key_params_str) = s.strip_prefix("FEC_KEY=") {
                let mut key_params: Vec<SrtpKeyParam> = Vec::new();

                for key_param in key_params_str.split(';') {
                    let key_param = SrtpKeyParam::from_str(key_param)?;
                    key_params.push(key_param);
                }
                SrtpSessionParam::FecKey(key_params)
            } else if let Some(wsh_val) = s.strip_prefix("WSH=") {
                let Ok(wsh_val) = wsh_val.parse::<u8>() else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "WSH".to_string(),
                        val: wsh_val.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                if wsh_val < 64 {
                    return Err(AttributeError::InvalidParamValue {
                        param: "WSH".to_string(),
                        val: wsh_val.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                }
                SrtpSessionParam::Wsh(wsh_val)
            } else {
                // Extension
                SrtpSessionParam::Extension(s.to_string())
            };
            session_params.push(param);
        }

        Ok(Self {
            tag,
            key_params,
            crypto_suite,
            session_params,
        })
    }
}

impl Display for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = self.tag.to_string();

        let crypto_suite_str = match &self.crypto_suite {
            CryptoSuite::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            CryptoSuite::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
            CryptoSuite::F8_128HmacSha1_80 => "F8_128_HMAC_SHA1_80",
            CryptoSuite::Other(s) => s.as_str(),
        };

        s += format!(" {}", crypto_suite_str).as_str();

        for (i, key_param) in self.key_params.iter().enumerate() {
            s += format!("{}{}", if i == 0 { ' ' } else { ';' }, key_param).as_str();
        }

        for session_param in &self.session_params {
            let param = match session_param {
                SrtpSessionParam::Kdr(kdr) => format!(" KDR={kdr}"),
                SrtpSessionParam::UnencryptedSrtp => " UNENCRYPTED_SRTP".to_string(),
                SrtpSessionParam::UnencryptedSrtcp => " UNENCRYPTED_SRTCP".to_string(),
                SrtpSessionParam::UnauthenticatedSrtp => " UNAUTHENTICATED_SRTP".to_string(),
                SrtpSessionParam::FecOrder(fec_order) => {
                    let order = match fec_order {
                        FecOrder::FecSrtp => "FEC_SRTP",
                        FecOrder::SrtpFec => "SRTP_FEC",
                    };
                    format!(" FEC_ORDER={order}")
                }
                SrtpSessionParam::FecKey(srtp_key_params) => {
                    let mut fec_keys = " FEC_KEY".to_string();
                    for (i, key_param) in srtp_key_params.iter().enumerate() {
                        fec_keys +=
                            format!("{}{}", if i == 0 { '=' } else { ';' }, key_param).as_str();
                    }
                    fec_keys
                }
                SrtpSessionParam::Wsh(wsh) => format!(" WSH={wsh}"),
                SrtpSessionParam::Extension(extn) => format!(" {extn}"),
            };

            s += param.as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for Crypto {
    const NAME: &'static str = "crypto";
}

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

/// Candidate connection address type
///
/// Can be IPv4, IPv6 or a FQDN
#[derive(Debug, PartialEq, Clone)]
pub enum CandidateAddress {
    IpAddr(IpAddr),
    FQDN(String),
}

/// ICE Candidate attribute of the media
///
/// See [RFC 8839 Section 5.1](https://datatracker.ietf.org/doc/html/rfc8839#section-5.1)
#[derive(Debug, PartialEq, Clone)]
pub struct Candidate {
    /// Arbitrary string used in the freezing algorithm to group similar candidates
    /// See [RFC 8445 Section 5.1.1.3](https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.3)
    pub foundation: String,
    /// Identifies the specific component of the data stream
    /// 1 for RTP and 2 for RTCP
    pub component_id: u32,
    /// Transport protocol of the candidate
    pub transport: String,
    /// Candidate's priority
    pub priority: u64,
    /// IP address of the candidate
    /// IPv4, IPv6 addresses and FQDN allowed
    pub address: CandidateAddress,
    /// Port of the candidate
    pub port: u16,
    /// Type of the candidate
    pub typ: CandidateType,
    /// Address related to the candidate
    /// Required for srflx, prflx and relay type candidates
    pub rel_addr: Option<IpAddr>,
    /// Port related to the candidate
    /// Required for srflx, prflx and relay type candidates
    pub rel_port: Option<u16>,
    /// Extensions
    pub extensions: Vec<(String, String)>,
}

impl FromStr for Candidate {
    type Err = AttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');

        let Some(foundation) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Foundation".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(comp_id) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Component id".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(comp_id) = comp_id.parse::<u32>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Component id".to_string(),
                val: comp_id.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(transport) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Transport".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(priority) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Priority".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(priority) = priority.parse::<u64>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Priority".to_string(),
                val: priority.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(address) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Address".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let address = match address.parse::<IpAddr>() {
            Ok(a) => CandidateAddress::IpAddr(a),
            Err(_) => CandidateAddress::FQDN(address.to_string()),
        };

        let Some(port) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Port".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Ok(port) = port.parse::<u16>() else {
            return Err(AttributeError::InvalidParamValue {
                param: "Port".to_string(),
                val: port.to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(typ_str) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "'typ' string".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        if !typ_str.eq_ignore_ascii_case("typ") {
            return Err(AttributeError::ParamNotFound {
                param: "'typ' string".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let Some(cand_type) = i.next() else {
            return Err(AttributeError::ParamNotFound {
                param: "Candidate type".to_string(),
                attr: <Self as TypedAttribute>::NAME.to_string(),
            });
        };

        let cand_type = if "host".eq_ignore_ascii_case(cand_type) {
            CandidateType::Host
        } else if "srflx".eq_ignore_ascii_case(cand_type) {
            CandidateType::Srflx
        } else if "prflx".eq_ignore_ascii_case(cand_type) {
            CandidateType::Prflx
        } else if "relay".eq_ignore_ascii_case(cand_type) {
            CandidateType::Relay
        } else {
            CandidateType::Other(cand_type.to_string())
        };

        let mut rel_addr: Option<IpAddr> = None;
        let mut rel_port: Option<u16> = None;
        let mut exts: Vec<(String, String)> = Vec::new();

        while let Some(key) = i.next() {
            if key.eq_ignore_ascii_case("raddr") {
                let Some(raddr) = i.next() else {
                    return Err(AttributeError::ParamNotFound {
                        param: "Relative address".to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                if let Ok(raddr) = raddr.parse::<IpAddr>() {
                    rel_addr = Some(raddr);
                } else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "Relative address".to_string(),
                        val: raddr.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };
            } else if key.eq_ignore_ascii_case("rport") {
                let Some(rport) = i.next() else {
                    return Err(AttributeError::ParamNotFound {
                        param: "Relative port".to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                if let Ok(rport) = rport.parse::<u16>() {
                    rel_port = Some(rport);
                } else {
                    return Err(AttributeError::InvalidParamValue {
                        param: "Relative port".to_string(),
                        val: rport.to_string(),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                }
            } else {
                let Some(val) = i.next() else {
                    return Err(AttributeError::Other {
                        error: format!("No val for the extension {key}"),
                        attr: <Self as TypedAttribute>::NAME.to_string(),
                    });
                };

                exts.push((key.to_string(), val.to_string()));
            }
        }

        Ok(Self {
            foundation: foundation.to_string(),
            component_id: comp_id,
            transport: transport.to_string(),
            priority,
            address,
            port,
            typ: cand_type,
            rel_addr,
            rel_port,
            extensions: exts,
        })
    }
}

impl Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let typ = match &self.typ {
            CandidateType::Host => "host".to_string(),
            CandidateType::Srflx => "srflx".to_string(),
            CandidateType::Prflx => "prflx".to_string(),
            CandidateType::Relay => "relay".to_string(),
            CandidateType::Other(o) => o.clone(),
        };

        let candidate_addr = match &self.address {
            CandidateAddress::IpAddr(a) => a.to_string(),
            CandidateAddress::FQDN(d) => d.clone(),
        };

        let mut s = format!(
            "{} {} {} {} {} {} typ {typ}",
            self.foundation,
            self.component_id,
            self.transport,
            self.priority,
            candidate_addr,
            self.port
        );

        if let Some(rel_addr) = self.rel_addr {
            s += format!(" raddr {rel_addr}").as_str();
        }
        if let Some(rel_port) = self.rel_port {
            s += format!(" rport {rel_port}").as_str();
        }

        for (key, val) in &self.extensions {
            s += format!(" {key} {val}").as_str();
        }

        f.write_str(&s)
    }
}

impl TypedAttribute for Candidate {
    const NAME: &'static str = "candidate";
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
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttributeError {
    /// If an Attribute is not found in a media or the session
    #[error("Attribute {} not found", .0)]
    NotFound(String),
    /// If a parameter is missing in an attribute
    #[error("Param {} not found in {}", .param, .attr)]
    ParamNotFound { param: String, attr: String },
    /// If a parameter value is not valid type or not in range
    #[error("Invalid value {} for Param {} in {}", .val ,.param, .attr)]
    InvalidParamValue {
        param: String,
        val: String,
        attr: String,
    },
    /// If an attribute is not in not in expected format
    #[error("Unsupported attribute format: {} for {}", .val, .attr)]
    UnsupportedFormat { val: String, attr: String },
    /// If there are more than expected items trailing in the attribute parameters
    #[error("Unexpected trailing item {} for in {}", .val, .attr)]
    UnexpectedTrailingItem { val: String, attr: String },
    /// Unspecified error
    #[error("{}: {}", .attr, .error)]
    Other { error: String, attr: String },
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
    /// Each item is a `Result` with the inferred type in `Ok` and `AttributeError` in `Err`.
    ///
    /// The iterator does not terminate upon an error item; continues with the next attribute
    pub fn attributes_typed<'a, T: TypedAttribute>(
        &'a self,
    ) -> impl Iterator<Item = Result<T, AttributeError>> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.attribute.eq_ignore_ascii_case(T::NAME))
            .map(|a| {
                let Some(s) = &a.value else {
                    // does not have a value for the attribute
                    return Err(AttributeError::Other {
                        error: "No value for the attribute".to_string(),
                        attr: T::NAME.to_string(),
                    });
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
    /// Each item is a `Result` with the inferred type in `Ok` and `AttributeError` in `Err`.
    ///
    /// The iterator does not terminate upon an error item; continues with the next attribute
    pub fn attributes_typed<'a, T: TypedAttribute>(
        &'a self,
    ) -> impl Iterator<Item = Result<T, AttributeError>> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.attribute.eq_ignore_ascii_case(T::NAME))
            .map(|a| {
                let Some(s) = &a.value else {
                    // does not have a value for the attribute
                    return Err(AttributeError::Other {
                        error: "No value for the attribute".to_string(),
                        attr: T::NAME.to_string(),
                    });
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
            .collect::<Vec<Result<RtpMap, AttributeError>>>();
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

    #[test]
    fn parse_setup_attribute() {
        let sdp = "v=0\r
m=image 54111 TCP t38\r
c=IN IP4 192.0.2.2\r
a=setup:actpass\r
a=connection:new\r
";
        let media = Session::parse(sdp.as_bytes()).unwrap().medias;

        let s = media[0].attributes_typed::<Setup>().collect::<Vec<_>>();

        assert_eq!(s.len(), 1);
        assert_eq!(s[0].as_ref().unwrap().to_owned(), Setup::ActPass);
    }

    #[test]
    fn parse_ssrc_attributes() {
        let sdp = "v=0\r
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r
m=video 49174 RTP/AVPF 96 98\r
a=rtpmap:98 rtx/90000\r
a=fmtp:98 apt=96;rtx-time=3000\r
a=ssrc-group:FID 11111 22222\r
a=ssrc:11111 cname:user3@example.com\r
a=ssrc:22222 fmtp:0 0-15\r
a=ssrc-group:FID 33333 44444\r
a=ssrc:33333 cname:user3@example.com\r
a=ssrc:44444 cname:user3@example.com\r
a=ssrc:1698359993 ts-refclk:ntp=pool.ntp.org
";

        let parsed = Session::parse(sdp.as_bytes()).unwrap();
        let m = &parsed.medias[0];

        let ssrcs = m
            .attributes_typed::<Ssrc>()
            .filter(|s| {
                let Ok(ssrc) = s else { return false };
                ssrc.attribute == SsrcAttribute::Fmtp
                    || matches!(ssrc.attribute, SsrcAttribute::Other(_))
            })
            .collect::<Vec<_>>();

        let ssrc_id = ssrcs[0].as_ref().unwrap().ssrc_id;

        let ssrc_groups = m
            .attributes_typed::<SsrcGroup>()
            .filter(|s| {
                let Ok(ssrc_group) = s else { return false };

                ssrc_group.ssrc_ids[1] == ssrc_id
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ssrc_groups[0].as_ref().unwrap().semantics,
            GroupSemantics::FID
        );

        assert_eq!(
            ssrcs[1].as_ref().unwrap().attribute,
            SsrcAttribute::Other("ts-refclk".to_string())
        );
    }

    #[test]
    fn parse_crypto_attributes() {
        let sdp = "v=0\r
o=sam 2890844526 2890842807 IN IP4 10.47.16.5\r
s=SRTP Discussion\r
i=A discussion of Secure RTP\r
u=http://www.example.com/seminars/srtp.pdf\r
e=marge@example.com (Marge Simpson)\r
c=IN IP4 168.2.17.12\r
t=2873397496 2873404696\r
m=audio 49170 RTP/SAVP 0\r
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 FEC_ORDER=SRTP_FEC\r
a=crypto:2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4;inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5|2^20|2:4 FEC_ORDER=FEC_SRTP\r
m=video 51372 RTP/SAVP 31\r
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1066:4\r
";

        let parsed = Session::parse(sdp.as_bytes()).unwrap();
        let a = &parsed.medias[0];

        let audio_cryptos = a.attributes_typed::<Crypto>().collect::<Vec<_>>();

        assert_eq!(
            audio_cryptos[0].as_ref().unwrap().crypto_suite,
            CryptoSuite::AesCm128HmacSha1_80
        );
        assert_eq!(audio_cryptos[1].as_ref().unwrap().key_params.len(), 2);

        assert_eq!(
            audio_cryptos[1].as_ref().unwrap().key_params[1].mki_and_length,
            Some((2, 4))
        );

        assert_eq!(
            audio_cryptos[1].as_ref().unwrap().session_params[0],
            SrtpSessionParam::FecOrder(FecOrder::FecSrtp)
        );

        let v = &parsed.medias[1];

        let video_cryptos = v
            .attributes_typed::<Crypto>()
            .filter(|c| {
                let Ok(crypto) = c else { return false };

                crypto.tag == 1
            })
            .collect::<Vec<_>>();

        let test_crypto = Crypto {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            key_params: vec![SrtpKeyParam {
                key_and_salt: "YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2".to_string(),
                lifetime: None,
                mki_and_length: Some((1066, 4)),
            }],
            session_params: Vec::new(),
        };

        assert_eq!(&test_crypto, video_cryptos[0].as_ref().unwrap());
    }

    #[test]
    fn write_crypto_attribute() {
        let crypto = Crypto {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            key_params: vec![
                SrtpKeyParam {
                    key_and_salt: "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz".to_string(),
                    lifetime: Some(1048576),
                    mki_and_length: Some((1, 4)),
                },
                SrtpKeyParam {
                    key_and_salt: "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz".to_string(),
                    lifetime: Some(1048576),
                    mki_and_length: Some((1, 4)),
                },
            ],
            session_params: vec![SrtpSessionParam::FecOrder(FecOrder::SrtpFec)],
        };

        assert_eq!(
            crypto.to_string(),
            "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4;inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 FEC_ORDER=SRTP_FEC"
        );
    }

    #[test]
    fn parse_candidate_attributes() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let sdp = "v=0\r
o=- 2890844526 2890842807 IN IP4 192.168.1.1\r
s=-\r
c=IN IP4 192.168.1.1\r
t=0 0\r
m=audio 49152 RTP/AVP 0\r
a=candidate:1 1 UDP 2130706432 192.168.1.1 49152 typ host raddr 10.0.1.1 rport 49153 generation 0\r
a=candidate:2 1 UDP 1692467200 10.0.1.1 49152 typ srflx raddr 192.168.1.1 rport 49153\r
a=candidate:3 2 UDP 1692467184 192.168.1.1 49153 typ host\r
a=candidate:4 1 UDP 100 2001:db8::1 49152 typ host\r
a=candidate:5 1 UDP 50 192.168.1.1 49154 typ prflx\r
a=candidate:6 1 UDP 25 192.168.1.1 49155 typ relay raddr 10.0.0.1 rport 49156\r
a=candidate:7 1 UDP 10 192.168.1.1 49157 typ unknown_type\r
";

        let session = Session::parse(sdp.as_bytes()).unwrap();
        let candidates: Vec<Candidate> =
            fallible_iterator::convert(session.medias[0].attributes_typed::<Candidate>())
                .collect::<Vec<_>>()
                .expect("Valid vector of candidates");

        assert_eq!(candidates.len(), 7);

        assert_eq!(candidates[0].foundation, "1");
        assert_eq!(candidates[0].component_id, 1);
        assert_eq!(
            candidates[0].address,
            CandidateAddress::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(candidates[0].port, 49152);
        assert_eq!(candidates[0].typ, CandidateType::Host);
        assert_eq!(
            candidates[0].rel_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)))
        );
        assert_eq!(candidates[0].rel_port, Some(49153));
        assert_eq!(
            candidates[0].extensions,
            vec![("generation".to_string(), "0".to_string())]
        );

        assert_eq!(candidates[1].foundation, "2");
        assert_eq!(candidates[1].typ, CandidateType::Srflx);
        assert_eq!(
            candidates[1].rel_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(candidates[1].rel_port, Some(49153));

        assert_eq!(candidates[2].foundation, "3");
        assert_eq!(candidates[2].component_id, 2);
        assert_eq!(candidates[2].typ, CandidateType::Host);

        assert_eq!(candidates[3].foundation, "4");
        assert_eq!(
            candidates[3].address,
            CandidateAddress::IpAddr(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(candidates[3].typ, CandidateType::Host);

        assert_eq!(candidates[4].foundation, "5");
        assert_eq!(candidates[4].typ, CandidateType::Prflx);

        assert_eq!(candidates[5].foundation, "6");
        assert_eq!(candidates[5].typ, CandidateType::Relay);

        assert_eq!(candidates[6].foundation, "7");
        assert_eq!(
            candidates[6].typ,
            CandidateType::Other("unknown_type".to_string())
        );
    }

    #[test]
    fn write_candidate() {
        use std::net::Ipv4Addr;

        let candidate = Candidate {
            foundation: "abcd/1234".into(),
            component_id: 1,
            transport: "UDP".into(),
            priority: 2130706432,
            address: CandidateAddress::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            port: 49152,
            typ: CandidateType::Srflx,
            rel_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            rel_port: Some(49153),
            extensions: vec![("tcptype".to_string(), "active".to_string())],
        };

        assert_eq!(
            candidate.to_string(),
            "abcd/1234 1 UDP 2130706432 192.168.0.1 49152 typ srflx raddr 10.0.0.1 rport 49153 tcptype active"
        );
    }

    #[test]
    fn test_attribute_errors() {
        // Test RtpMap error paths
        assert_eq!(
            "99".parse::<RtpMap>().unwrap_err(),
            AttributeError::UnsupportedFormat {
                val: "99".to_string(),
                attr: "rtpmap".to_string()
            }
        );
        assert_eq!(
            "abc 90000".parse::<RtpMap>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Payload type".to_string(),
                val: "abc".to_string(),
                attr: "rtpmap".to_string()
            }
        );
        assert_eq!(
            "200 enc/90000".parse::<RtpMap>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Payload type".to_string(),
                val: "200(expected 0-127)".to_string(),
                attr: "rtpmap".to_string()
            }
        );
        assert_eq!(
            "99 ".parse::<RtpMap>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Clock rate".to_string(),
                attr: "rtpmap".to_string()
            }
        );
        assert_eq!(
            "99 /".parse::<RtpMap>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Clock rate".to_string(),
                val: "".to_string(),
                attr: "rtpmap".to_string()
            }
        );

        // Test Fmtp error paths
        assert_eq!(
            "invalid".parse::<Fmtp>().unwrap_err(),
            AttributeError::UnsupportedFormat {
                val: "invalid".to_string(),
                attr: "fmtp".to_string()
            }
        );
        assert_eq!(
            "abc profile=1".parse::<Fmtp>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "fmtp".to_string(),
                val: "abc".to_string(),
                attr: "fmtp".to_string()
            }
        );

        // Test Rtcp error paths
        assert_eq!(
            "".parse::<Rtcp>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Port".to_string(),
                val: "".to_string(),
                attr: "rtcp".to_string()
            }
        );
        assert_eq!(
            "abc IN IP4 127.0.0.1".parse::<Rtcp>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Port".to_string(),
                val: "abc".to_string(),
                attr: "rtcp".to_string()
            }
        );
        assert_eq!(
            "53020 invalid IP4 127.0.0.1".parse::<Rtcp>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Network type".to_string(),
                val: "invalid".to_string(),
                attr: "rtcp".to_string()
            }
        );

        // Test Fingerprint error paths
        assert_eq!(
            "".parse::<Fingerprint>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Hash value".to_string(),
                attr: "fingerprint".to_string()
            }
        );
        assert_eq!(
            "SHA-1".parse::<Fingerprint>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Hash value".to_string(),
                attr: "fingerprint".to_string()
            }
        );

        // Test Candidate error paths
        assert_eq!(
            "".parse::<Candidate>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Component id".to_string(),
                attr: "candidate".to_string()
            }
        );
        assert_eq!(
            "1 1 UDP 100".parse::<Candidate>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Address".to_string(),
                attr: "candidate".to_string()
            }
        );

        // Test ExtMap error paths
        assert_eq!(
            "".parse::<ExtMap>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Id".to_string(),
                val: "".to_string(),
                attr: "extmap".to_string()
            }
        );
        assert_eq!(
            "999999 http://example.com".parse::<ExtMap>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Id".to_string(),
                val: "999999".to_string(),
                attr: "extmap".to_string()
            }
        );

        // Test Group error paths
        assert_eq!(
            "".parse::<Group>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Media identification tags".to_string(),
                attr: "group".to_string()
            }
        );
        assert_eq!(
            "LS".parse::<Group>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Media identification tags".to_string(),
                attr: "group".to_string()
            }
        );

        // Test Ssrc error paths
        assert_eq!(
            "".parse::<Ssrc>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Ssrc id".to_string(),
                attr: "ssrc".to_string()
            }
        );
        assert_eq!(
            "abc".parse::<Ssrc>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Ssrc id".to_string(),
                attr: "ssrc".to_string()
            }
        );

        // Test Setup error paths
        let setup_err = "foo".parse::<Setup>().err().unwrap();
        assert!(matches!(setup_err, AttributeError::Other { .. }));
        assert_eq!(format!("{}", setup_err), "setup: Invalid Setup value foo");

        // Test Crypto error paths
        assert_eq!(
            "".parse::<Crypto>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Tag".to_string(),
                val: "".to_string(),
                attr: "crypto".to_string()
            }
        );
        assert_eq!(
            "abc AES_CM_128_HMAC_SHA1_32 inline:key"
                .parse::<Crypto>()
                .unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Tag".to_string(),
                val: "abc".to_string(),
                attr: "crypto".to_string()
            }
        );

        // Test RtcpFb error paths
        assert_eq!(
            "".parse::<RtcpFb>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Payload format".to_string(),
                val: "".to_string(),
                attr: "rtcp-fb".to_string()
            }
        );
        assert_eq!(
            "*".parse::<RtcpFb>().unwrap_err(),
            AttributeError::ParamNotFound {
                param: "Rtcp feedback value".to_string(),
                attr: "rtcp-fb".to_string()
            }
        );
        assert_eq!(
            "1 ack ccfb".parse::<RtcpFb>().unwrap_err(),
            AttributeError::InvalidParamValue {
                param: "Payload type".to_string(),
                val: "1(expected wildcard (*))".to_string(),
                attr: "rtcp-fb".to_string()
            }
        );

        // Test attribute_typed with missing value
        let media = Media {
            media: "video".into(),
            port: 1234,
            num_ports: None,
            proto: "RTP/SAVPF".into(),
            fmt: "".into(),
            media_title: None,
            connections: vec![],
            bandwidths: vec![],
            key: None,
            attributes: vec![Attribute {
                attribute: "rtpmap".into(),
                value: None,
            }],
        };
        assert_eq!(
            media
                .attributes_typed::<RtpMap>()
                .collect::<Vec<Result<RtpMap, AttributeError>>>()
                .remove(0)
                .unwrap_err(),
            AttributeError::Other {
                error: "No value for the attribute".to_string(),
                attr: "rtpmap".to_string()
            }
        );
    }
}
