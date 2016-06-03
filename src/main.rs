use std::mem;
use std::io::Error;

extern crate libc;
use libc::{c_int, c_void, socket, sendto, AF_INET, SOCK_RAW, sockaddr_in, in_addr, sockaddr};
static IPPROTO_ICMP: c_int = 1;

/*#[derive(Debug)]
struct Ipv4Header {
    ver_hlen: u8,
    services: u8,
    len: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    src: u32,
    dst: u32,
}

impl Ipv4Header {
    fn new_header() -> Ipv4Header {
        let header = Ipv4Header { ver_hlen: (4<<4 | 5) & 0xff, services: 0, len: 5, id: 1337, flags_fragment: 0, ttl: 255, proto: 1, checksum: 0, src: 0, dst: 0 };
        header
    }
    fn to_byte_array(&self) -> [u8; 20] {
        let mut buffer = [0; 20];
        buffer[0] = self.ver_hlen;
        buffer[1] = self.services;
        buffer[2] = (self.len>>8 & 0xFF) as u8;
        buffer[3] = (self.len & 0xFF) as u8;
        buffer[4] = (self.id>>8 & 0xFF) as u8;
        buffer[5] = (self.id & 0xFF) as u8;
        buffer[6] = (self.flags_fragment>>8 & 0xFF) as u8;
        buffer[7] = (self.flags_fragment & 0xFF) as u8;
        buffer[8] = self.ttl;
        buffer[9] = self.proto;
        buffer[10] = (self.checksum>>8 & 0xFF) as u8;
        buffer[11] = (self.checksum & 0xFF) as u8;
        buffer[12] = (self.src>>24 & 0xFF) as u8;
        buffer[13] = (self.src>>16 & 0xFF) as u8;
        buffer[14] = (self.src>>8 & 0xFF) as u8;
        buffer[15] = (self.src & 0xFF) as u8;
        buffer[16] = (self.dst>>24 & 0xFF) as u8;
        buffer[17] = (self.dst>>16 & 0xFF) as u8;
        buffer[18] = (self.dst>>8 & 0xFF) as u8;
        buffer[19] = (self.dst & 0xFF) as u8;
        buffer
    }
}*/

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
        let mut icmpheader = ICMPHeader { icmp_type: 8, code: 0, checksum: 0, header: header };
        let checksum = ICMPHeader::calc_checksum(&icmpheader.to_byte_array());
        icmpheader.checksum = checksum;
        icmpheader
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

fn get_icmp_socket() -> Result<i32, String> {
    let handle = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if handle == -1 {
        return Err(std::error::Error::description(&Error::last_os_error()).to_string());
    }
    Ok(handle)
}

fn send_packet(handle: i32, destination: &str, buffer: &[u8]) -> Result<u32, String> {
    let mut split_destination = destination.split(".");
    let first = split_destination.next().expect("Invalid IP-address").parse::<u32>().expect("Invalid IP-address");
    let second = split_destination.next().expect("Invalid IP-address").parse::<u32>().expect("Invalid IP-address");
    let third = split_destination.next().expect("Invalid IP-address").parse::<u32>().expect("Invalid IP-address");
    let fourth = split_destination.next().expect("Invalid IP-address").parse::<u32>().expect("Invalid IP-address");

    let addr = sockaddr_in{ sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr{ s_addr: (fourth<<24 | third<<16 | second<<8 | first) as u32}, sin_zero: [0; 8]};
    let addr2: sockaddr = unsafe {mem::transmute(addr)};
    let pktlength = unsafe { sendto(handle, buffer.as_ptr() as *mut c_void, buffer.len(), 0, &addr2 as *const sockaddr, 16) };
    if pktlength == -1 {
        return Err(std::error::Error::description(&Error::last_os_error()).to_string()); 
    }
    Ok(pktlength as u32)
}

fn main() {
    let handle = get_icmp_socket().expect("Could not create socket");
    let icmpheader = ICMPHeader::echo_request(15, 27).to_byte_array();
    send_packet(handle, "130.89.12.10", &icmpheader).expect("Could not send packet");
}

#[cfg(test)]
mod tests {
    use super::ICMPHeader;

    #[test]
    fn checksum() {
        let test1 = vec![0b00001000u8, 0b00000000u8, 0b00000000u8, 0b00000000u8, 0b00000000u8, 0b00000001u8, 0b00000000u8, 0b00001001u8, 0b01010100u8, 0b01000101u8, 0b01010011u8, 0b01010100u8];
        let mut checksum = ICMPHeader::calc_checksum(&test1);
        assert_eq!(checksum, 20572);
        
        //Example from wikipedia IPV4
        let test2 = vec![0x45u8, 0x00, 0x00, 0x73, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
        checksum = ICMPHeader::calc_checksum(&test2);
        assert_eq!(checksum, 0xb861);
    }
}
