extern crate tuntap;
extern crate libc;
extern crate eui48;
extern crate core;

use tuntap::{TunTap, Tap, Ipv4};
use std::net::Ipv4Addr;
use std::collections::HashMap;
use eui48::MacAddress;
use std::mem;

trait Packet {}
trait ArpPacket {}

#[repr(C, packed)]
struct EthHdr<T: Packet> {
    dmac: MacAddress,
    smac: MacAddress,
    ethertype: EtherType,
    payload: T,
}

#[cfg(target_endian = "little")]
#[derive(Debug, Clone)]
#[repr(u16)]
// NOTE: the bytes are swapped because this hardware is little endian but
// the network in big endian
enum EtherType {
    Unknown = 0x0000,
    Ipv4 = 0x0008,
    Arp = 0x0608,
    Ipv6 = 0xdd86,
}

#[cfg(target_endian = "big")]
#[derive(Debug)]
#[repr(u16)]
enum EtherType {
    Unknown = 0x0000,
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86dd,
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct ArpHdr<T: ArpPacket> {
    hwtype: HwType,
    protype: EtherType,
    hwsize: u8,
    prosize: u8,
    opcode: OpCode,
    data: T,
}

impl Packet for [u8; 1486] {}
impl<T: ArpPacket> Packet for ArpHdr<T> {}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct Ipv4Arp {
    smac: MacAddress,
    sip: Ipv4Addr,
    dmac: MacAddress,
    dip: Ipv4Addr,
}

impl ArpPacket for [u8; 1478] {}
impl ArpPacket for Ipv4Arp {}

#[cfg(target_endian = "big")]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(u16)]
enum HwType {
    Unknown = 0x0000,
    Ethernet = 0x0001,
}

#[cfg(target_endian = "big")]
#[derive(Debug, Clone)]
#[repr(u16)]
enum OpCode {
    Unknown = 0x0000,
    Request = 0x0001,
    Reply = 0x0002,
}

#[cfg(target_endian = "little")]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[repr(u16)]
enum HwType {
    Unknown = 0x0000,
    Ethernet = 0x0100,
}

#[cfg(target_endian = "little")]
#[derive(Debug, Clone)]
#[repr(u16)]
enum OpCode {
    Unknown = 0x0000,
    Request = 0x0100,
    Reply = 0x0200,
}

// fn data_format(data: &[u8]) -> String {
//    let mut data_string: String = "".to_string();
//
//    for (i, c) in data.iter().enumerate() {
//        if i % 4 == 0 {
//            data_string.push(' ');
//        }
//        if i % 8 == 0 {
//            data_string.push('\n');
//        }
//
//        data_string.push_str(&format!("{:02x} ", c));
//    }
//
//    data_string
// }

fn main() {
    let mut tap = TunTap::create(Tap, Ipv4);

    println!("tap name: {:?}", tap.get_name());
    let address = [10, 0, 0, 1];
    let address_str = format!("{}.{}.{}.{}",
                              address[0],
                              address[1],
                              address[2],
                              address[3]);
    let mac: [u8; 6] = [0x00, 0x20, 0x91, 0x50, 0xe2, 0x43];

    tap.set_mac(mac);
    tap.up();
    tap.add_address(&address_str);

    let mut arp_map = HashMap::new();

    loop {
        let mut b: [u8; 1500] = [0; 1500];

        let _len = tap.read(&mut b).unwrap();

        let eth: EthHdr<[u8; 1486]> = unsafe { mem::transmute(b) };

        if let EtherType::Arp = eth.ethertype {
            let etharp: EthHdr<ArpHdr<[u8; 1478]>> = unsafe { mem::transmute(eth) };

            if let (&HwType::Ethernet, &EtherType::Ipv4) = (&etharp.payload.hwtype,
                                                            &etharp.payload.protype) {
                let mut b: [u8; 42] = [0; 42];
                let raw: [u8; 1500] = unsafe { mem::transmute(etharp) };
                for i in 0..42 {
                    b[i] = raw[i];
                }
                let mut ipv4arp: EthHdr<ArpHdr<Ipv4Arp>> = unsafe { mem::transmute(b) };

                arp_map.insert((ipv4arp.payload.hwtype.clone(), ipv4arp.payload.data.sip),
                               ipv4arp.payload.data.smac);

                if let OpCode::Request = ipv4arp.payload.opcode {
                    ipv4arp.dmac = ipv4arp.smac;
                    ipv4arp.smac = MacAddress::new(mac);
                    ipv4arp.payload.opcode = OpCode::Reply;
                    ipv4arp.payload.data.dmac = ipv4arp.payload.data.smac;
                    ipv4arp.payload.data.smac = MacAddress::new(mac);
                    ipv4arp.payload.data.dip = ipv4arp.payload.data.sip;
                    ipv4arp.payload.data.sip = Ipv4Addr::new(address[0],
                                                             address[1],
                                                             address[2],
                                                             address[3]);

                    let rep: [u8; 42] = unsafe { mem::transmute(ipv4arp) };

                    tap.write(&rep).unwrap();
                }
            }
        }
    }
}
