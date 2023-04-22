// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This is an example of usage zettabgp.
//! Application connects to specified BGP peer and prints incoming messages

extern crate zettabgp;

use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread::{sleep, spawn};
use zettabgp::prelude::*;

pub struct BgpDumper {
    pub params: BgpSessionParams,
    pub stream: TcpStream,
}
impl BgpDumper {
    pub fn new(bgp_params: BgpSessionParams, tcpstream: TcpStream) -> BgpDumper {
        BgpDumper {
            params: bgp_params,
            stream: tcpstream,
        }
    }
    fn recv_message_head(&mut self) -> Result<(BgpMessageType, usize), BgpError> {
        let mut buf = [0_u8; 19];
        self.stream.read_exact(&mut buf)?;
        self.params.decode_message_head(&buf)
    }
    pub fn start_active(&mut self) -> Result<(), BgpError> {
        let mut bom = self.params.open_message();
        let mut buf = [255_u8; 4096];
        let messagelen = match bom.encode_to(&self.params, &mut buf[19..]) {
            Err(e) => {
                return Err(e);
            }
            Ok(sz) => sz,
        };
        let blen = self
            .params
            .prepare_message_buf(&mut buf, BgpMessageType::Open, messagelen)?;
        self.stream.write_all(&buf[0..blen])?;
        let msg = match self.recv_message_head() {
            Err(e) => {
                return Err(e);
            }
            Ok(msg) => msg,
        };
        if msg.0 != BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid state to start_active"));
        }
        self.stream.read_exact(&mut buf[0..msg.1])?;
        bom.decode_from(&self.params, &buf[0..msg.1])?;
        self.params.hold_time = bom.hold_time;
        self.params.caps = bom.caps;
        self.params.check_caps();
        Ok(())
    }
    pub fn send_keepalive(stream: &mut TcpStream) -> Result<(), BgpError> {
        let mut buf = [255_u8; 19];
        buf[0..16].clone_from_slice(&[255_u8; 16]);
        buf[16] = 0;
        buf[17] = 19;
        buf[18] = 4; //keepalive
        match stream.write_all(&buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn start_keepalives(&self) -> Result<(), BgpError> {
        let mut ks = self.stream.try_clone()?;
        let slp = std::time::Duration::new((self.params.hold_time / 3) as u64, 0);
        spawn(move || loop {
            if BgpDumper::send_keepalive(&mut ks).is_err() {
                break;
            }
            sleep(slp);
        });
        Ok(())
    }
    pub fn lifecycle(&mut self) -> Result<(), BgpError> {
        self.start_keepalives()?;
        let mut buf = Box::new([0_u8; 65536]);
        loop {
            let msg = match self.recv_message_head() {
                Ok(m) => m,
                Err(e) => {
                    return Err(e);
                }
            };
            if msg.0 == BgpMessageType::Keepalive {
                continue;
            }
            self.stream.read_exact(&mut buf[0..msg.1])?;
            match msg.0 {
                BgpMessageType::Open => {
                    eprintln!("Incorrect open message!");
                    break;
                }
                BgpMessageType::Keepalive => {}
                BgpMessageType::Notification => {
                    let mut msgnotification = BgpNotificationMessage::new();
                    match msgnotification.decode_from(&self.params, &buf[0..msg.1]) {
                        Err(e) => {
                            eprintln!("BGP notification decode error: {:?}", e);
                        }
                        Ok(_) => {
                            println!(
                                "BGP notification: {:?} - {:?}",
                                msgnotification,
                                msgnotification.error_text()
                            );
                        }
                    };
                    break;
                }
                BgpMessageType::Update => {
                    let mut msgupdate = BgpUpdateMessage::new();
                    if let Err(e) = msgupdate.decode_from(&self.params, &buf[0..msg.1]) {
                        eprintln!("BGP update decode error: {:?}", e);
                        continue;
                    }
                    println!("{:?}", msgupdate);
                }
            }
        }
        Ok(())
    }
    pub fn close(&mut self) {
        self.stream.shutdown(Shutdown::Both).unwrap_or_default();
    }
}

fn main() {
    env_logger::init();
    if env::args().len() != 3 {
        eprintln!("Usage: bgpdumper PEER AS");
        return;
    }
    let vargs: Vec<String> = env::args().collect();
    let targetip: std::net::IpAddr = match vargs[1].parse() {
        Ok(x) => x,
        Err(_) => {
            eprintln!("Invalid peer IP - {}", vargs[1]);
            return;
        }
    };
    let targetasn: u32 = match vargs[2].parse() {
        Ok(x) => x,
        Err(_) => {
            eprintln!("Invalid peer ASn - {}", vargs[2]);
            return;
        }
    };
    let target = std::net::SocketAddr::new(targetip, 179);
    let stream = std::net::TcpStream::connect(target).expect("Unable to connect to bgp speaker");
    let mut peer = BgpDumper::new(
        BgpSessionParams::new(
            targetasn,
            180,
            BgpTransportMode::IPv4,
            std::net::Ipv4Addr::new(1, 0, 0, 0),
            vec![
                BgpCapability::SafiIPv4u,
                BgpCapability::SafiIPv4m,
                BgpCapability::SafiIPv4lu,
                BgpCapability::SafiIPv6lu,
                BgpCapability::SafiVPNv4u,
                BgpCapability::SafiVPNv4m,
                BgpCapability::SafiVPNv6u,
                BgpCapability::SafiVPNv6m,
                BgpCapability::SafiIPv4mvpn,
                BgpCapability::SafiVPLS,
                BgpCapability::CapRR,
                BgpCapability::CapASN32(targetasn),
            ]
            .into_iter()
            .collect(),
        ),
        stream,
    );
    if let Err(e) = peer.start_active() {
        eprintln!("failed to create BGP peer; err = {:?}", e);
        peer.close();
        return;
    };
    println!("Run lifecycle");
    peer.lifecycle().unwrap();
    println!("Done lifecycle");
    peer.close();
}
