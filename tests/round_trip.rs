use sdp_types::attributes::*;
use sdp_types::enums::*;

// Helper: parse a string, display it, assert it equals the canonical form.
macro_rules! round_trip {
    ($t:ty, $s:expr) => {{
        let val: $t = $s.parse().expect(concat!("failed to parse: ", $s));
        assert_eq!(val.to_string(), $s);
    }};
}

// Helper: parse a string, display it, assert it equals a different canonical form.
macro_rules! round_trip_canonical {
    ($t:ty, $input:expr, $canonical:expr) => {{
        let val: $t = $input.parse().expect(concat!("failed to parse: ", $input));
        assert_eq!(val.to_string(), $canonical);
    }};
}

// ── enums ────────────────────────────────────────────────────────────────────

#[test]
fn net_type_round_trip() {
    round_trip!(NetType, "IN");
    round_trip!(NetType, "TN");
    round_trip!(NetType, "ATM");
    round_trip!(NetType, "PSTN");
}

#[test]
fn net_type_case_insensitive() {
    round_trip_canonical!(NetType, "in", "IN");
    round_trip_canonical!(NetType, "tn", "TN");
    round_trip_canonical!(NetType, "atm", "ATM");
    round_trip_canonical!(NetType, "pstn", "PSTN");
}

#[test]
fn net_type_invalid() {
    assert!("OTHER".parse::<NetType>().is_err());
}

#[test]
fn addr_type_round_trip() {
    round_trip!(AddrType, "IP4");
    round_trip!(AddrType, "IP6");
}

#[test]
fn addr_type_case_insensitive() {
    round_trip_canonical!(AddrType, "ip4", "IP4");
    round_trip_canonical!(AddrType, "ip6", "IP6");
}

#[test]
fn addr_type_invalid() {
    assert!("IP5".parse::<AddrType>().is_err());
}

#[test]
fn bandwidth_type_round_trip() {
    round_trip!(BandwidthType, "AS");
    round_trip!(BandwidthType, "CT");
    round_trip!(BandwidthType, "RR");
    round_trip!(BandwidthType, "RS");
}

#[test]
fn bandwidth_type_case_insensitive() {
    round_trip_canonical!(BandwidthType, "as", "AS");
    round_trip_canonical!(BandwidthType, "ct", "CT");
    round_trip_canonical!(BandwidthType, "rr", "RR");
    round_trip_canonical!(BandwidthType, "rs", "RS");
}

#[test]
fn bandwidth_type_invalid() {
    assert!("TIAS".parse::<BandwidthType>().is_err());
}

#[test]
fn key_method_round_trip() {
    round_trip!(KeyMethod, "clear");
    round_trip!(KeyMethod, "base64");
    round_trip!(KeyMethod, "uri");
    round_trip!(KeyMethod, "prompt");
}

#[test]
fn key_method_case_sensitive() {
    // KeyMethod is explicitly case-sensitive (RFC 8866)
    assert!("CLEAR".parse::<KeyMethod>().is_err());
    assert!("Base64".parse::<KeyMethod>().is_err());
}

#[test]
fn media_type_round_trip() {
    round_trip!(MediaType, "audio");
    round_trip!(MediaType, "video");
    round_trip!(MediaType, "text");
    round_trip!(MediaType, "application");
    round_trip!(MediaType, "message");
    round_trip!(MediaType, "image");
}

#[test]
fn media_type_case_insensitive() {
    round_trip_canonical!(MediaType, "AUDIO", "audio");
    round_trip_canonical!(MediaType, "Video", "video");
}

#[test]
fn media_type_invalid() {
    assert!("unknown".parse::<MediaType>().is_err());
}

#[test]
fn transport_proto_round_trip() {
    round_trip!(TransportProto, "udp");
    round_trip!(TransportProto, "RTP/AVP");
    round_trip!(TransportProto, "RTP/SAVP");
    round_trip!(TransportProto, "RTP/SAVPF");
}

#[test]
fn transport_proto_case_insensitive() {
    round_trip_canonical!(TransportProto, "UDP", "udp");
    round_trip_canonical!(TransportProto, "rtp/avp", "RTP/AVP");
    round_trip_canonical!(TransportProto, "rtp/savp", "RTP/SAVP");
    round_trip_canonical!(TransportProto, "rtp/savpf", "RTP/SAVPF");
}

#[test]
fn transport_proto_invalid() {
    assert!("SCTP".parse::<TransportProto>().is_err());
}

// ── attribute enums ──────────────────────────────────────────────────────────

#[test]
fn direction_round_trip() {
    round_trip!(Direction, "sendonly");
    round_trip!(Direction, "recvonly");
    round_trip!(Direction, "sendrecv");
    round_trip!(Direction, "inactive");
}

#[test]
fn direction_case_insensitive() {
    round_trip_canonical!(Direction, "SENDONLY", "sendonly");
    round_trip_canonical!(Direction, "RecvOnly", "recvonly");
    round_trip_canonical!(Direction, "SENDRECV", "sendrecv");
    round_trip_canonical!(Direction, "INACTIVE", "inactive");
}

#[test]
fn direction_invalid() {
    assert!("halfduplex".parse::<Direction>().is_err());
}

#[test]
fn setup_round_trip() {
    round_trip!(Setup, "active");
    round_trip!(Setup, "passive");
    round_trip!(Setup, "actpass");
    round_trip!(Setup, "holdconn");
}

#[test]
fn setup_case_insensitive() {
    round_trip_canonical!(Setup, "ACTIVE", "active");
    round_trip_canonical!(Setup, "Passive", "passive");
    round_trip_canonical!(Setup, "ACTPASS", "actpass");
    round_trip_canonical!(Setup, "HOLDCONN", "holdconn");
}

// ── RtpMap ───────────────────────────────────────────────────────────────────

#[test]
fn rtpmap_round_trip() {
    // without encoding params
    round_trip!(RtpMap, "0 PCMU/8000");
    round_trip!(RtpMap, "98 H263-1998/90000");
    round_trip!(RtpMap, "8 PCMA/8000");
    // with encoding params
    round_trip!(RtpMap, "97 MPEG4-GENERIC/48000/2");
    round_trip!(RtpMap, "96 opus/48000/2");
}

#[test]
fn rtpmap_errors() {
    assert!("99".parse::<RtpMap>().is_err());
    assert!("abc PCMU/8000".parse::<RtpMap>().is_err());
    assert!("200 enc/90000".parse::<RtpMap>().is_err());
    assert!("99 ".parse::<RtpMap>().is_err());
}

// ── Fmtp ─────────────────────────────────────────────────────────────────────

#[test]
fn fmtp_round_trip() {
    // single param without value
    round_trip!(Fmtp, "97 0-15");
    // single key=value
    round_trip!(Fmtp, "98 profile-level-id=42");
    // multiple key=value params
    round_trip!(Fmtp, "98 profile-level-id=1;mode=0");
    // mixed params
    round_trip!(Fmtp, "99 vbr=on;dtx=1;mode=0");
}

#[test]
fn fmtp_errors() {
    assert!("invalid".parse::<Fmtp>().is_err());
    assert!("abc profile=1".parse::<Fmtp>().is_err());
}

// ── Rtcp ─────────────────────────────────────────────────────────────────────

#[test]
fn rtcp_round_trip() {
    round_trip!(Rtcp, "53020 IN IP4 127.0.0.1");
    round_trip!(Rtcp, "9 IN IP6 ::1");
    round_trip!(Rtcp, "5004 IN IP4 192.168.1.1");
}

// ── RtcpFb ───────────────────────────────────────────────────────────────────

#[test]
fn rtcpfb_round_trip() {
    // ack variants
    round_trip!(RtcpFb, "* ack");
    round_trip!(RtcpFb, "98 ack rpsi");
    round_trip!(RtcpFb, "* ack app");
    round_trip!(RtcpFb, "* ack app myapp");
    round_trip!(RtcpFb, "* ack ccfb");
    // nack variants
    round_trip!(RtcpFb, "* nack");
    round_trip!(RtcpFb, "98 nack pli");
    round_trip!(RtcpFb, "98 nack sli");
    round_trip!(RtcpFb, "98 nack rpsi");
    round_trip!(RtcpFb, "98 nack app");
    round_trip!(RtcpFb, "98 nack app myapp");
    round_trip!(RtcpFb, "98 nack ecn");
    // trr-int
    round_trip!(RtcpFb, "* trr-int 0");
    round_trip!(RtcpFb, "* trr-int 1000");
    // ccm variants
    round_trip!(RtcpFb, "98 ccm fir");
    round_trip!(RtcpFb, "98 ccm tstr");
    round_trip!(RtcpFb, "* ccm tmmbr");
    round_trip!(RtcpFb, "* ccm tmmbr smaxpr=120");
    round_trip!(RtcpFb, "98 ccm vbcm 1 2");
    // other
    round_trip!(RtcpFb, "* custom-feedback");
}

// ── ExtMap ───────────────────────────────────────────────────────────────────

#[test]
fn extmap_round_trip() {
    // without direction or attributes
    round_trip!(ExtMap, "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level");
    round_trip!(ExtMap, "2 urn:ietf:params:rtp-hdrext:mid");
    // with direction
    round_trip!(
        ExtMap,
        "1/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level"
    );
    round_trip!(ExtMap, "2/recvonly urn:ietf:params:rtp-hdrext:mid");
    round_trip!(ExtMap, "3/sendrecv urn:ietf:params:rtp-hdrext:mid");
    round_trip!(ExtMap, "4/inactive urn:ietf:params:rtp-hdrext:mid");
    // with attributes
    round_trip!(ExtMap, "5 urn:ietf:params:rtp-hdrext:mid some-attr");
    // with direction and attributes
    round_trip!(
        ExtMap,
        "6/sendrecv urn:ietf:params:rtp-hdrext:mid some-attr"
    );
    // with multi-word attributes
    round_trip!(
        ExtMap,
        "7 urn:ietf:params:rtp-hdrext:mid some attr with spaces"
    );
    round_trip!(
        ExtMap,
        "8/sendonly urn:ietf:params:rtp-hdrext:mid some attr with spaces"
    );
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

#[test]
fn fingerprint_round_trip() {
    // sha-1 (20 bytes)
    round_trip!(
        Fingerprint,
        "sha-1 CD:34:D1:1E:5A:5A:89:57:1F:C0:04:47:20:32:11:7C:41:4F:82:41"
    );
    // sha-256 (32 bytes)
    round_trip!(
        Fingerprint,
        "sha-256 3A:96:6D:57:B2:C2:C7:61:A0:46:3E:1C:97:39:D3:F7:0A:88:A0:B1:EC:03:FB:10:A5:5D:3A:37:AB:DD:02:AA"
    );
    // sha-224 (28 bytes)
    round_trip!(
        Fingerprint,
        "sha-224 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"
    );
    // sha-384 (48 bytes)
    round_trip!(
        Fingerprint,
        "sha-384 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45"
    );
    // sha-512 (64 bytes)
    round_trip!(
        Fingerprint,
        "sha-512 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67"
    );
    // md-5 (16 bytes)
    round_trip!(
        Fingerprint,
        "md-5 FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF"
    );
    // md-2 (16 bytes)
    round_trip!(
        Fingerprint,
        "md-2 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
    );
}

#[test]
fn fingerprint_case_insensitive_hash_func() {
    round_trip_canonical!(
        Fingerprint,
        "SHA-1 CD:34:D1:1E:5A:5A:89:57:1F:C0:04:47:20:32:11:7C:41:4F:82:41",
        "sha-1 CD:34:D1:1E:5A:5A:89:57:1F:C0:04:47:20:32:11:7C:41:4F:82:41"
    );
}

// ── Group ────────────────────────────────────────────────────────────────────

#[test]
fn group_round_trip() {
    round_trip!(Group, "LS 1 2");
    round_trip!(Group, "FID 1 2 3");
    round_trip!(Group, "SRF audio video");
    round_trip!(Group, "ANAT audio video");
    round_trip!(Group, "FEC 1 2");
    round_trip!(Group, "DDP 1 2 3 4");
    // Other semantics
    round_trip!(Group, "BUNDLE audio video data");
}

#[test]
fn group_case_insensitive_semantics() {
    round_trip_canonical!(Group, "ls 1 2", "LS 1 2");
    round_trip_canonical!(Group, "fid 1 2 3", "FID 1 2 3");
    // Other semantics preserve original case — "bundle" stays "bundle"
    round_trip!(Group, "BUNDLE audio video");
}

// ── Ssrc ─────────────────────────────────────────────────────────────────────

#[test]
fn ssrc_round_trip() {
    // cname with value
    round_trip!(Ssrc, "3735928559 cname:alice@atlanta.com");
    // previous-ssrc without value
    round_trip!(Ssrc, "1234567890 previous-ssrc");
    // fmtp with value
    round_trip!(Ssrc, "1234567890 fmtp:0 0-15");
    // other attribute
    round_trip!(Ssrc, "1698359993 ts-refclk:ntp=pool.ntp.org");
    // attribute without value
    round_trip!(Ssrc, "999 cname");
}

#[test]
fn ssrc_case_insensitive_attribute() {
    round_trip_canonical!(
        Ssrc,
        "3735928559 CNAME:alice@atlanta.com",
        "3735928559 cname:alice@atlanta.com"
    );
    round_trip_canonical!(Ssrc, "1234567890 PREVIOUS-SSRC", "1234567890 previous-ssrc");
    round_trip_canonical!(Ssrc, "1234567890 FMTP:params", "1234567890 fmtp:params");
}

// ── SsrcGroup ────────────────────────────────────────────────────────────────

#[test]
fn ssrc_group_round_trip() {
    round_trip!(SsrcGroup, "FID 3735928559 1234567890");
    round_trip!(SsrcGroup, "FEC 1000000000 2000000000 3000000000");
    round_trip!(SsrcGroup, "LS 111 222 333");
}

#[test]
fn ssrc_group_case_insensitive_semantics() {
    round_trip_canonical!(SsrcGroup, "fid 11111 22222", "FID 11111 22222");
}

// ── SrtpKeyParam ─────────────────────────────────────────────────────────────

#[test]
fn srtp_key_param_round_trip() {
    // key only
    round_trip!(
        SrtpKeyParam,
        "inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
    );
    // with power-of-two lifetime
    round_trip!(
        SrtpKeyParam,
        "inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20"
    );
    // with lifetime and MKI
    round_trip!(
        SrtpKeyParam,
        "inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4"
    );
    // with non-power-of-two lifetime and MKI
    round_trip!(
        SrtpKeyParam,
        "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1066:4"
    );
    // with MKI only (no lifetime)
    round_trip!(
        SrtpKeyParam,
        "inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|2:4"
    );
}

// ── Crypto ───────────────────────────────────────────────────────────────────

#[test]
fn crypto_round_trip() {
    // single key param, no session params
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
    );
    // with lifetime and MKI
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4"
    );
    // AES_CM_128_HMAC_SHA1_32
    round_trip!(
        Crypto,
        "2 AES_CM_128_HMAC_SHA1_32 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4"
    );
    // F8_128_HMAC_SHA1_80
    round_trip!(
        Crypto,
        "3 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4"
    );
    // multiple key params
    round_trip!(
        Crypto,
        "2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4;inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5|2^20|2:4"
    );
    // with session params
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 FEC_ORDER=SRTP_FEC"
    );
    round_trip!(
        Crypto,
        "2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4;inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5|2^20|2:4 FEC_ORDER=FEC_SRTP"
    );
    // with non-power-of-two lifetime
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1066:4"
    );
    // other session params
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz UNENCRYPTED_SRTP"
    );
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz UNENCRYPTED_SRTCP"
    );
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz UNAUTHENTICATED_SRTP"
    );
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz KDR=16"
    );
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz WSH=64"
    );
    // FEC_KEY with single key param
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz FEC_KEY=inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5"
    );
    // FEC_KEY with multiple key params
    round_trip!(
        Crypto,
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz FEC_KEY=inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5;inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm"
    );
}

#[test]
fn crypto_case_insensitive_suite() {
    round_trip_canonical!(
        Crypto,
        "1 aes_cm_128_hmac_sha1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
        "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
    );
}

// ── Candidate ────────────────────────────────────────────────────────────────

#[test]
fn candidate_round_trip() {
    // host, no optional fields
    round_trip!(Candidate, "1 1 UDP 2130706432 192.168.1.1 49152 typ host");
    // host, IPv6
    round_trip!(Candidate, "4 1 UDP 100 2001:db8::1 49152 typ host");
    // srflx with raddr/rport
    round_trip!(
        Candidate,
        "2 1 UDP 1692467200 10.0.1.1 49152 typ srflx raddr 192.168.1.1 rport 49153"
    );
    // prflx
    round_trip!(Candidate, "5 1 UDP 50 192.168.1.1 49154 typ prflx");
    // relay with raddr/rport
    round_trip!(
        Candidate,
        "6 1 UDP 25 192.168.1.1 49155 typ relay raddr 10.0.0.1 rport 49156"
    );
    // with extensions
    round_trip!(
        Candidate,
        "1 1 UDP 2130706432 192.168.1.1 49152 typ host raddr 10.0.1.1 rport 49153 generation 0"
    );
    round_trip!(
        Candidate,
        "abcd/1234 1 UDP 2130706432 192.168.0.1 49152 typ srflx raddr 10.0.0.1 rport 49153 tcptype active"
    );
    // FQDN address
    round_trip!(
        Candidate,
        "1 1 UDP 2130706432 host.example.com 49152 typ host"
    );
    // Other candidate type
    round_trip!(Candidate, "7 1 UDP 10 192.168.1.1 49157 typ unknown_type");
}

#[test]
fn candidate_case_insensitive_typ_and_extensions() {
    // candidate types should be case-insensitive
    round_trip_canonical!(
        Candidate,
        "1 1 UDP 2130706432 192.168.1.1 49152 typ HOST",
        "1 1 UDP 2130706432 192.168.1.1 49152 typ host"
    );
    round_trip_canonical!(
        Candidate,
        "2 1 UDP 100 10.0.0.1 49152 typ SRFLX raddr 192.168.1.1 rport 49153",
        "2 1 UDP 100 10.0.0.1 49152 typ srflx raddr 192.168.1.1 rport 49153"
    );
    // raddr and rport keys should be case-insensitive
    round_trip_canonical!(
        Candidate,
        "2 1 UDP 100 10.0.0.1 49152 typ srflx RADDR 192.168.1.1 RPORT 49153",
        "2 1 UDP 100 10.0.0.1 49152 typ srflx raddr 192.168.1.1 rport 49153"
    );
}
