use std::time::Instant;

/// Abstract congestion controller API.
pub trait CongestionController {
    fn on_packet_sent(&mut self, bytes: u64, now: Instant);
    fn on_ack(&mut self, bytes: u64, now: Instant);
    fn on_congestion_event(&mut self, now: Instant);
    fn on_spurious_congestion_event(&mut self);
    fn bytes_in_flight(&self) -> u64;
    fn cwnd(&self) -> u64;
    fn can_send(&self, datagram_size: usize) -> bool;
}

/// NewReno congestion controller (RFC 9002 Appendix B).
#[derive(Debug, Clone)]
pub struct NewReno {
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    max_datagram_size: u64,
    recovery_start: Option<Instant>,
}

impl NewReno {
    pub fn new(max_datagram_size: u64) -> Self {
        let initial_window = 10 * max_datagram_size.max(1200);
        Self {
            cwnd: initial_window,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            max_datagram_size,
            recovery_start: None,
        }
    }

    fn in_recovery(&self) -> bool {
        self.recovery_start.is_some()
    }
}

impl CongestionController for NewReno {
    fn on_packet_sent(&mut self, bytes: u64, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    fn on_ack(&mut self, bytes: u64, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes.min(self.bytes_in_flight));

        if self.in_recovery() {
            // First ACK for packet sent during recovery exits recovery.
            self.recovery_start = None;
            return;
        }

        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd = self.cwnd.saturating_add(bytes);
        } else {
            // Congestion avoidance
            let additive = (self.max_datagram_size * bytes) / self.cwnd.max(self.max_datagram_size);
            self.cwnd = self.cwnd.saturating_add(additive.max(1));
        }
    }

    fn on_congestion_event(&mut self, now: Instant) {
        if self.in_recovery() {
            return;
        }
        self.ssthresh = (self.cwnd / 2).max(2 * self.max_datagram_size);
        self.cwnd = self.ssthresh;
        self.recovery_start = Some(now);
        if self.bytes_in_flight > self.cwnd {
            self.bytes_in_flight = self.cwnd;
        }
    }

    fn on_spurious_congestion_event(&mut self) {
        self.cwnd = self.cwnd.max(self.ssthresh);
        self.recovery_start = None;
    }

    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn cwnd(&self) -> u64 {
        self.cwnd
    }

    fn can_send(&self, datagram_size: usize) -> bool {
        let datagram_size = datagram_size as u64;
        self.bytes_in_flight + datagram_size <= self.cwnd
    }
}
