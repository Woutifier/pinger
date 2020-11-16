// MIT License
//
// Copyright (c) 2016 Wouter B. de Vries
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
extern crate byteorder;
extern crate libc;

use std::mem;
use std::io::{Error, Cursor};
use std::thread::sleep;
use std::time::Duration;
use std::net::{Ipv6Addr, IpAddr};
use std::str::FromStr;

// Use other than std
use libc::{c_int, c_void, socket, sendto, AF_INET, AF_INET6, SOCK_RAW, sockaddr_in, sockaddr_in6,
           in_addr, sockaddr, bind};
use self::byteorder::{ReadBytesExt, LittleEndian};

// Static values
static IPPROTO_ICMP: c_int = 1;
static IPPROTO_ICMPV6: c_int = 58;

enum SockAddr {
    V4(sockaddr_in),
    V6(sockaddr_in6),
}

#[derive(Debug)]
pub struct ICMP6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub header: u32,
}

impl ICMP6Header {
    pub fn echo_request(identifier: u16, sequence_number: u16) -> ICMP6Header {
        let header = ((identifier as u32) << 16) | (sequence_number as u32);
        let mut icmp6_header = ICMP6Header {
            icmp_type: 128,
            code: 0,
            checksum: 0,
            header: header,
        };
        let checksum = ICMP6Header::calc_checksum(&icmp6_header.to_byte_array());
        icmp6_header.checksum = checksum;
        icmp6_header
    }

    pub fn to_byte_array(&self) -> [u8; 8] {
        let mut buffer = [0; 8];
        buffer[0] = self.icmp_type;
        buffer[1] = self.code;
        buffer[2] = (self.checksum >> 8 & 0xFF) as u8;
        buffer[3] = (self.checksum & 0xFF) as u8;
        buffer[4] = (self.header >> 24 & 0xFF) as u8;
        buffer[5] = (self.header >> 16 & 0xFF) as u8;
        buffer[6] = (self.header >> 8 & 0xFF) as u8;
        buffer[7] = (self.header & 0xFF) as u8;
        buffer
    }

    fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut size = buffer.len();
        let mut checksum: u32 = 0;
        while size > 0 {
            let word = (buffer[buffer.len() - size] as u16) << 8 |
                       (buffer[buffer.len() - size + 1]) as u16;
            checksum += word as u32;
            size -= 2;
        }
        let remainder = checksum >> 16;
        checksum &= 0xFFFF;
        checksum += remainder;
        checksum ^= 0xFFFF;
        checksum as u16
    }
}

#[derive(Debug)]
pub struct ICMP4Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub header: u32,
    pub payload_sec: u64,
    pub payload_nanosec: u32,
    pub dest_part1: u8,
    pub dest_part2: u8,
    pub dest_part3: u8,
    pub dest_part4: u8,
}

impl ICMP4Header {
    pub fn echo_request(identifier: u16, sequence_number: u16, payload_sec: u64, payload_nanosec: u32, dest_ip: &str) -> ICMP4Header {
        let header = ((identifier as u32) << 16) | (sequence_number as u32);

        let split = dest_ip.split(".");
        let vec: Vec<&str> = split.collect();		
        let first_part: u8 = vec[0].parse().unwrap();
        let second_part: u8 = vec[1].parse().unwrap();
        let third_part: u8 = vec[2].parse().unwrap();
        let fourth_part: u8 = vec[3].parse().unwrap();

        let mut icmp4_header = ICMP4Header {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            header: header,
            payload_sec: payload_sec,
            payload_nanosec: payload_nanosec,
            dest_part1: first_part,
            dest_part2: second_part,
            dest_part3: third_part,
            dest_part4: fourth_part,
        };
        let checksum = ICMP4Header::calc_checksum(&icmp4_header.to_byte_array());
        icmp4_header.checksum = checksum;
        icmp4_header
    }

    pub fn to_byte_array(&self) -> [u8; 24] {
        let mut buffer = [0; 24];
        buffer[0] = self.icmp_type;
        buffer[1] = self.code;
        buffer[2] = (self.checksum >> 8 & 0xFF) as u8;
        buffer[3] = (self.checksum & 0xFF) as u8;
        buffer[4] = (self.header >> 24 & 0xFF) as u8;
        buffer[5] = (self.header >> 16 & 0xFF) as u8;
        buffer[6] = (self.header >> 8 & 0xFF) as u8;
        buffer[7] = (self.header & 0xFF) as u8;
        buffer[8] = (self.dest_part1 & 0xFF) as u8;
        buffer[9] = (self.dest_part2 & 0xFF) as u8;
        buffer[10] = (self.dest_part3 & 0xFF) as u8;
        buffer[11] = (self.dest_part4 & 0xFF) as u8;
        buffer[12] = (self.payload_sec >> 56 & 0xFF) as u8;
        buffer[13] = (self.payload_sec >> 48 & 0xFF) as u8;
        buffer[14] = (self.payload_sec >> 40 & 0xFF) as u8;
        buffer[15] = (self.payload_sec >> 32 & 0xFF) as u8;
        buffer[16] = (self.payload_sec >> 24 & 0xFF) as u8;
        buffer[17] = (self.payload_sec >> 16 & 0xFF) as u8;
        buffer[18] = (self.payload_sec >> 8 & 0xFF) as u8;
        buffer[19] = (self.payload_sec & 0xFF) as u8;
        buffer[20] = (self.payload_nanosec >> 24 & 0xFF) as u8;
        buffer[21] = (self.payload_nanosec >> 16 & 0xFF) as u8;
        buffer[22] = (self.payload_nanosec >> 8 & 0xFF) as u8;
        buffer[23] = (self.payload_nanosec & 0xFF) as u8;

        buffer
    }

    fn calc_checksum(buffer: &[u8]) -> u16 {
        let mut size = buffer.len();
        let mut checksum: u32 = 0;
        while size > 0 {
            let word = (buffer[buffer.len() - size] as u16) << 8 |
                       (buffer[buffer.len() - size + 1]) as u16;
            checksum += word as u32;
            size -= 2;
        }
        let remainder = checksum >> 16;
        checksum &= 0xFFFF;
        checksum += remainder;
        checksum ^= 0xFFFF;
        checksum as u16
    }
}

pub fn new_icmpv4_socket() -> Result<i32, String> {
    let handle = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if handle == -1 {
        return Err(::std::error::Error::description(&Error::last_os_error()).to_string());
    }
    Ok(handle)
}

pub fn new_icmpv6_socket() -> Result<i32, String> {
    let handle = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) };
    if handle == -1 {
        return Err(::std::error::Error::description(&Error::last_os_error()).to_string());
    }
    Ok(handle)
}

fn to_sockaddr(input: SockAddr) -> Option<*const sockaddr> {
    if let SockAddr::V4(input) = input {
        return Some((&input as *const sockaddr_in) as *const sockaddr);
    } else if let SockAddr::V6(input) = input {
        return Some((&input as *const sockaddr_in6) as *const sockaddr);
    }
    None
}

pub fn bind_to_ip(handle: i32, ip: &str) -> Result<(), String> {
    let addr = string_to_sockaddr(ip);
	// println!("Bolod:{}", ip);
    if let Some(addr) = addr {
        let retval = unsafe { bind(handle, to_sockaddr(addr).unwrap(), 16) };
        if retval != 0 {
            return Err(::std::error::Error::description(&Error::last_os_error()).to_string());
        }
        return Ok(());
    }
    Err("Invalid IP-address".to_string())
}


fn string_to_sockaddr(ip: &str) -> Option<SockAddr> {
    let dest_ip = IpAddr::from_str(ip);
    if let Ok(IpAddr::V4(dest_ip)) = dest_ip {
        let mut ipcursor = Cursor::new(dest_ip.octets());
        //println!("{:?}", ipcursor.read_u32::<LittleEndian>().unwrap());
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: in_addr { s_addr: ipcursor.read_u32::<LittleEndian>().unwrap() },
            sin_zero: [0; 8],
        };
        return Some(SockAddr::V4(addr));
    } else if let Ok(IpAddr::V6(dest_ip)) = dest_ip {
        let addr = sockaddr_in6 {
            sin6_flowinfo: 0,
            sin6_port: 0,
            sin6_scope_id: 0,
            sin6_family: AF_INET6 as u16,
            sin6_addr: init_in6_addr(dest_ip),
        };
        return Some(SockAddr::V6(addr));
    }
    None
}

// Todo: this function needs cleaning up
fn init_in6_addr(addr: Ipv6Addr) -> libc::in6_addr {
    let mut bytes = addr.segments();
    bytes.reverse();
    let mut stuff: [u8; 16] = unsafe { mem::transmute(bytes) };
    stuff.reverse();
    unsafe {
        let mut in6addr: libc::in6_addr = mem::uninitialized();
        in6addr.s6_addr = stuff;
        return in6addr;
    };
}

pub fn send_packet(handlev4: i32,
                   handlev6: i32,
                   destination: &str,
                   bufferv4: &[u8],
                   bufferv6: &[u8])
                   -> Result<u32, String> {
    let addr = string_to_sockaddr(destination);
    if let Some(addr) = addr {
        let mut pktlength = -1;
        while pktlength == -1 {
            if let SockAddr::V4(addr) = addr {
                pktlength = unsafe {
                    sendto(handlev4,
                           bufferv4.as_ptr() as *mut c_void,
                           bufferv4.len(),
                           0,
                           (&addr as *const sockaddr_in) as *const sockaddr,
                           16)
                };
            } else if let SockAddr::V6(addr) = addr {
                pktlength = unsafe {
                    sendto(handlev6,
                           bufferv6.as_ptr() as *mut c_void,
                           bufferv6.len(),
                           0,
                           (&addr as *const sockaddr_in6) as *const sockaddr,
                           28)
                };
            }
            // sleep(Duration::from_secs(1));
            if pktlength == -1 {
                let syserr = Error::last_os_error();
                if syserr.raw_os_error().is_some() && syserr.raw_os_error().unwrap() == 105 {
                    sleep(Duration::from_millis(1));
                } else {
                    println!("Error: {}", syserr);
                    return Err(::std::error::Error::description(&syserr).to_string());
                }
            }
        }
        return Ok(pktlength as u32);
    }
    Err(format!("Invalid IP-Address: {}", destination))
}

#[cfg(test)]
mod tests {
    use super::ICMP4Header;

    #[test]
    fn checksum() {
        // Example from some other source
        let test1 = vec![0b00001000u8,
                         0b00000000u8,
                         0b00000000u8,
                         0b00000000u8,
                         0b00000000u8,
                         0b00000001u8,
                         0b00000000u8,
                         0b00001001u8,
                         0b01010100u8,
                         0b01000101u8,
                         0b01010011u8,
                         0b01010100u8];
        let mut checksum = ICMP4Header::calc_checksum(&test1);
        assert_eq!(checksum, 20572);

        // Example from wikipedia IPV4
        let test2 = vec![0x45u8, 0x00, 0x00, 0x73, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
                         0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
        checksum = ICMP4Header::calc_checksum(&test2);
        assert_eq!(checksum, 0xb861);
    }
}
