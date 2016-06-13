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

extern crate time;
use time::precise_time_ns;

pub struct TokenBucketFilter {
    enabled: bool,
    rate: u64,
    bucket: u64,
    last_time: u64,
    ns_per_packet: u64,
}

impl TokenBucketFilter {
    pub fn new(rate: u64) -> TokenBucketFilter {
        let mut ns_per_packet = 0;
        if rate > 0 {
            ns_per_packet = (1000000000 as u64)/rate;
        }
        let tbf = TokenBucketFilter { enabled: rate > 0, rate: rate, bucket: 0, last_time: precise_time_ns(), ns_per_packet: ns_per_packet };
        tbf
    }

    pub fn take(&mut self) {
        if !self.enabled {
            return;
        }
        while self.bucket == 0 {
            let current_time = precise_time_ns();
            let diff_time = current_time - self.last_time;
            if diff_time > self.ns_per_packet {
                let tokens = diff_time/self.ns_per_packet;
                self.bucket = ::std::cmp::min(self.bucket + tokens, self.rate);
                self.last_time = current_time;
            }
        }
        self.bucket -= 1;
    }
}
