use std::net::UdpSocket;
use std::usize;
use std::mem;
use std::env;
use std::net::IpAddr;

extern crate libc;
use libc::{c_int, c_void, socket, AF_INET, sockaddr_storage, SOCK_RAW};
static IPPROTO_ICMP: c_int = 1;

#[derive(Debug)]
struct ICMPHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    header: u32
}

impl ICMPHeader {
    fn echo_request(identifier: u16, sequence_number: u16) -> ICMPHeader {
        let header = ((identifier as u32)<<16)  | (sequence_number as u32);
         ICMPHeader { icmp_type: 8, code: 0, checksum: 0, header: header }
    }
 
    fn to_byte_array(&self) -> [u8; 8] {
       let mut buffer = [0; 8];
        buffer[0] = self.icmp_type;
        buffer[1] = self.code;
        buffer[2] = (self.checksum>>8 & 0xFF) as u8;
        buffer[3] = (self.checksum & 0xFF) as u8;
        buffer[4] = (self.header>>24 & 0xFF) as u8;
        buffer[5] = (self.header>>16 & 0xFF) as u8;
        buffer[6] = (self.header>>8 & 0xFF) as u8;
        buffer[7] = (self.header & 0xFF) as u8;
        buffer
    }

    fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut size = buffer.len();
        let mut checksum: u32 = 0;
        while size > 0 {
            let word = (buffer[buffer.len()-size] as u16)<<8 | (buffer[buffer.len()-size+1]) as u16;
            checksum += word as u32;
            size -= 2;
        }
        let remainder = checksum>>16;
        checksum &= 0xFFFF;
        checksum += remainder;
        checksum ^= 0xFFFF;
        checksum as u16
    }
}

fn main() {
    let handle = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    let icmpheader = ICMPHeader::echo_request(1, 1);
    let checksum = ICMPHeader::calc_checksum(&icmpheader.to_byte_array());
    println!("{:b} {:b}", checksum>>8, checksum&0xff);
}

#[cfg(test)]
mod tests {
    use super::ICMPHeader;

    #[test]
    fn checksum() {
        let tester = vec![0b00001000u8, 0b00000000u8, 0b00000000u8, 0b00000000u8, 0b00000000u8, 0b00000001u8, 0b00000000u8, 0b00001001u8, 0b01010100u8, 0b01000101u8, 0b01010011u8, 0b01010100u8];
        let checksum = ICMPHeader::calc_checksum(&tester);
        assert_eq!(checksum, 20572);
    }
}
