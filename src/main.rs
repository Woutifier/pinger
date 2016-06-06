//MIT License
//
//Copyright (c) 2016 Wouter B. de Vries
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

mod net;
extern crate libc;
extern crate argparse;
use std::io::{self, Read, BufRead};
use argparse::{ArgumentParser, Store};

fn main() {
    //let mut inputfile = "".to_string();
    let mut saddr = "".to_string();
    let mut rate = 0;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Performs pings to IP-addresses received from STDIN");
        //ap.refer(&mut inputfile)
        //.add_argument("FILE", Store, "File to read");
        ap.refer(&mut saddr)
        .add_option(&["-s", "--source-address"], Store, "Source IP");
        ap.refer(&mut rate)
        .add_option(&["-r", "--rate-limit"], Store, "Rate-limit packets per second");
        ap.parse_args_or_exit();
    }
    
    let sock = net::new_icmp_socket().expect("Could not create socket");

    if !saddr.is_empty() {
        net::bind_to_ip(sock, &saddr).expect("Could not bind socket to source address");
    }

    let mut buffer = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let icmpheader = net::ICMPHeader::echo_request(1337, 1).to_byte_array();
    while handle.read_line(&mut buffer).unwrap() > 0 {
        net::send_packet(sock, buffer.trim(), &icmpheader).expect("Could not send packet");
        buffer.clear();
    }
}

