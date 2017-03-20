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

mod net;
mod tbf;
extern crate libc;
extern crate argparse;
extern crate time;
use std::io::{self, BufRead};
use argparse::{ArgumentParser, Store};

fn main() {
    // Read arguments from commandline
    let mut saddr = "".to_string();
    let mut rate = 0;
    let mut identifier = 1337;
    let mut sequence_number = 1;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Performs pings to IP-addresses received from STDIN");
        ap.refer(&mut saddr)
          .add_option(&["-s", "--source-address"], Store, "Source IP");
        ap.refer(&mut rate)
          .add_option(&["-r", "--rate-limit"],
                      Store,
                      "Rate-limit packets per second");
        ap.refer(&mut identifier)
          .add_option(&["-i", "--identifier"],
                        Store,
                        "Identifier value to use in Echo Request");
        ap.refer(&mut sequence_number)
            .add_option(&["-n", "--sequence-number"],
                        Store,
                        "Sequence number to use in Echo Request");
        ap.parse_args_or_exit();
    }

    // Setup socket & (optionally) bind address
    let sockv4 = net::new_icmpv4_socket().expect("Could not create socket (v4)");
    if !saddr.is_empty() {
        net::bind_to_ip(sockv4, &saddr).expect("Could not bind socket to source address");
    }

    let sockv6 = net::new_icmpv6_socket().expect("Could not create socket (v6)");

    
    // Read from STDIN
    let mut buffer = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // Create new ICMP-header (IPv4 and IPv6)
    let icmp4header = net::ICMP4Header::echo_request(identifier, sequence_number).to_byte_array();
    let icmp6header = net::ICMP6Header::echo_request(identifier, sequence_number).to_byte_array();

    // Initialize TokenBucketFilter for rate-limiting
    let mut tbf = tbf::TokenBucketFilter::new(rate);

    // Send packets in a while loop from STDIN
    while handle.read_line(&mut buffer).unwrap() > 0 {
        // Ratelimit
        tbf.take();

        // Send packet
        let result = net::send_packet(sockv4, sockv6, buffer.trim(), &icmp4header, &icmp6header);
        if result.is_err() {
            println!("Could not send packet");
        }
        buffer.clear();
    }
}
