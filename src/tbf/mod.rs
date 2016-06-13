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
