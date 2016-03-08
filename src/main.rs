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
trait Ipv4Packet {}
trait IcmpPacket {}
trait PingPayload {}

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

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct Ipv4Hdr<T: Ipv4Packet> {
    version_ihl: VersionIhl,
    dscp_ecn: DscpEcn,
    length: u16,
    id: u16,
    flags_offset: FlagsOffset,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    sip: Ipv4Addr,
    dip: Ipv4Addr,
    options_data: T,
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct IcmpHdr<T: IcmpPacket> {
    typ: IcmpType,
    code: u8,
    checksum: u16,
    rest: T,
}

impl Ipv4Packet for [u8; 1466] {}
impl <T: IcmpPacket> Ipv4Packet for IcmpHdr<T> {}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct PingPacket<T: PingPayload> {
    id: u16,
    seq: u16,
    payload: T,
}

impl <T: PingPayload> IcmpPacket for PingPacket<T> {}
impl IcmpPacket for [u8; 1462] {}

impl PingPayload for [u8; 1458] {}

#[derive(Debug, Clone)]
#[repr(u8)]
enum IcmpType {
    Unsupported = 0xff,
    EchoReply = 0x00,
    EchoRequest = 0x08,
}

#[derive(Debug, Clone)]
#[repr(u8)]
enum Protocol {
    Unknown = 0xff,
    Icmp = 0x01,
    Igmp = 0x02,
    Tcp = 0x06,
    Udp = 0x11,
    Encap = 0x29,
    Ospf = 0x59,
    Sctp = 0x84,
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct VersionIhl {
    version_ihl: u8,
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct DscpEcn {
    dscp_ecn: u8,
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct FlagsOffset{
    flags_offset: u16,
}

impl VersionIhl {
    fn version(&self) -> u8 {
        (self.version_ihl & 0b11110000) / 16
    }
    fn ihl(&self) -> u8 {
        self.version_ihl & 0b00001111
    }
}

impl FlagsOffset {
    fn bit0(&self) -> bool {
        false
    }

    fn bit1(&self) -> bool {
        (self.flags_offset & 0b0100000000000000) == 1
    }

    fn bit2(&self) -> bool {
        (self.flags_offset & 0b0010000000000000) == 1
    }

    fn offset(&self) -> u16 {
        self.flags_offset & 0b0001111111111111
    }
}

impl Packet for [u8; 1486] {}
impl<T: ArpPacket> Packet for ArpHdr<T> {}
impl<T: Ipv4Packet> Packet for Ipv4Hdr<T> {}

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

fn checksum(data: &[u8], len: u16) -> u16 {
    let mut sum = 0u32;
    let mut i: usize = 0;
    while i < len as usize {
        let word = (*data.get(i).unwrap() as u32) << 8 | *data.get(i+1).unwrap() as u32;
        sum = sum + word;
        i = i + 2;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    u16::to_be(!sum as u16)
}

fn data_format(data: &[u8], end: usize) -> String {
   let mut data_string: String = "".to_string();
   let finish_at = if end == 0 {
       data.len()
   } else {
       end
   };

   for (i, c) in data.iter().enumerate() {
       if i == finish_at {
           break;
       }
       if i % 4 == 0 {
           data_string.push(' ');
       }
       if i % 8 == 0 {
           data_string.push('\n');
       }

       data_string.push_str(&format!("{:02x} ", c));
   }

   data_string
}

fn main() {
    let mut tap = TunTap::create(Tap, Ipv4);

    println!("tap name: {:?}", tap.get_name());
    let address = [10, 0, 0, 1];
    let mac: [u8; 6] = [0x00, 0x20, 0x91, 0x50, 0xe2, 0x43];

    tap.set_mac(mac);
    tap.up();

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
        } else if let EtherType::Ipv4 = eth.ethertype {
            let ethipv4: EthHdr<Ipv4Hdr<[u8; 1466]>> = unsafe { mem::transmute(eth) };
            if ethipv4.payload.version_ihl.ihl() != 5 {
                panic!("IPv4 options not supported!");
            }

            if let Protocol::Icmp = ethipv4.payload.protocol {
                let ethicmp: EthHdr<Ipv4Hdr<IcmpHdr<[u8; 1462]>>> = unsafe {
                    mem::transmute(ethipv4)
                };
                let icmplen = u16::to_be(ethicmp.payload.length) - 20;

                if let IcmpType::EchoRequest = ethicmp.payload.options_data.typ {
                    let mut ethping: EthHdr<Ipv4Hdr<IcmpHdr<PingPacket<[u8; 1458]>>>> = unsafe {
                        mem::transmute(ethicmp)
                    };

                    ethping.dmac = ethping.smac;
                    ethping.smac = MacAddress::new(mac);
                    ethping.payload.dip = ethping.payload.sip;
                    ethping.payload.sip = Ipv4Addr::new(address[0],
                                                        address[1],
                                                        address[2],
                                                        address[3]);
                    ethping.payload.options_data.typ = IcmpType::EchoReply;
                    ethping.payload.options_data.checksum = 0x0000;
                    let mut ethipv4: EthHdr<Ipv4Hdr<[u8; 1466]>> = unsafe {
                        mem::transmute(ethping)
                    };
                    let icmpcs = checksum(&ethipv4.payload.options_data, icmplen);
                    ethipv4.payload.checksum = 0x0000;
                    let eth: EthHdr<[u8; 1486]> = unsafe { mem::transmute(ethipv4) };
                    let ipv4cs = checksum(&eth.payload, 20);
                    let mut ethping: EthHdr<Ipv4Hdr<IcmpHdr<PingPacket<[u8; 1458]>>>> = unsafe {
                        mem::transmute(eth)
                    };
                    ethping.payload.options_data.checksum = icmpcs;
                    ethping.payload.checksum = ipv4cs;

                    let send: [u8; 1500] = unsafe { mem::transmute(ethping) };
                    tap.write(&send).unwrap();
                }
            }
        } else {
            println!("Unknown packet type");
            println!("smac: {}\ndmac: {}\nethertype: {:?}", eth.dmac, eth.smac,
                     eth.ethertype);
            println!("data: {}\n", data_format(&eth.payload, _len));
        }
    }
}
