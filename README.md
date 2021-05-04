zettabgp - BGP&BMP Rust library
====================

This is a BGP and BMP protocols driver library for Rust.

BGP - Border Gateway Protocol version 4.
BMP - BGP Monitoring Protocol version 3.

## Supported BGP message types
 * Open
 * Notification
 * Keepalive
 * Update

## Supported BMP message types
 * Initiation
 * Termination
 * PeerUpNotification
 * RouteMonitoring

## Supported address families NLRI (network layer reachability information)
 * ipv4 unicast
 * ipv4 labeled-unicast
 * ipv4 multicast
 * ipv4 mvpn
 * vpnv4 unicast
 * vpnv4 multicast
 * ipv6 unicast
 * ipv6 labeled-unicast
 * ipv6 multicast
 * vpnv6 unicast
 * vpnv6 multicast
 * vpls
 * evpn
 * flowspec ipv4
 * flowspec ipv6

## Supported path attributes
 * MED
 * Origin
 * Local preference
 * AS path
 * Communities
 * Extended communities
 * Aggregator AS
 * Atomic aggregate
 * Cluster list
 * Originator ID
 * Attribute set
 * some PMSI tunnels

## Usage

Library allow you to parse protocol messages (as binary buffers) into Rust data structures to frther processing.
Or generate valid protocol messages from Rust data structure.
So it can be use in any environment (synrchronous or asynchronous) to make a BGP RR, monitoring system or BGP analytics.

```rust
use zettabgp::prelude::*;
use std::io::{Read,Write};
let mut socket = match std::net::TcpStream::connect("127.0.0.1:179") {
  Ok(sck) => sck,
  Err(e) => {eprintln!("Unable to connect to BGP neighbor: {}",e);return;}
};
let params=BgpSessionParams::new(64512,180,BgpTransportMode::IPv4,std::net::Ipv4Addr::new(1,1,1,1),vec![BgpCapability::SafiIPv4u].into_iter().collect());
let mut buf = [0 as u8; 32768];
let mut open_my = params.open_message();
let open_sz = open_my.encode_to(&params, &mut buf[19..]).unwrap();
let tosend = params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();
socket.write_all(&buf[0..tosend]).unwrap();//send my open message
socket.read_exact(&mut buf[0..19]).unwrap();//read response message head
let messagehead=params.decode_message_head(&buf).unwrap();//decode message head
if messagehead.0 == BgpMessageType::Open {
   socket.read_exact(&mut buf[0..messagehead.1]).unwrap();//read message body
   let mut bom = BgpOpenMessage::new();
   bom.decode_from(&params, &buf[0..messagehead.1]).unwrap();//decode received message body
   eprintln!("BGP Open message received: {:?}", bom);
}
```


## Crates.io

https://crates.io/crates/zettabgp

## Documentation

https://docs.rs/zettabgp

## License

[MIT OR Apache-2.0](LICENSE)