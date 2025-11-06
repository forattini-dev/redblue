use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::congestion::{CongestionController, NewReno};
use super::frame::{AckFrame, AckRange};
use super::packet::{PacketNumber, PacketNumberSpace};

/// Tracked packet metadata for loss detection.
#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: PacketNumber,
    pub packet_number_space: PacketNumberSpace,
    pub time_sent: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    pub in_flight: bool,
}

impl SentPacket {
    pub fn new(
        packet_number: PacketNumber,
        packet_number_space: PacketNumberSpace,
        size: usize,
        ack_eliciting: bool,
        in_flight: bool,
    ) -> Self {
        Self {
            packet_number,
            packet_number_space,
            time_sent: Instant::now(),
            size,
            ack_eliciting,
            in_flight,
        }
    }
}

/// Loss recovery manager implementing RFC 9002 logic.
#[derive(Debug)]
pub struct LossRecovery {
    pub latest_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub rttvar: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub pto_count: u32,
    pub loss_time: Option<Instant>,
    pub controller: NewReno,
    outstanding: VecDeque<SentPacket>,
}

impl LossRecovery {
    pub fn new(max_datagram_size: u64) -> Self {
        Self {
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: None,
            min_rtt: None,
            pto_count: 0,
            loss_time: None,
            controller: NewReno::new(max_datagram_size),
            outstanding: VecDeque::new(),
        }
    }

    pub fn on_packet_sent(&mut self, mut packet: SentPacket) {
        packet.time_sent = Instant::now();
        if packet.in_flight {
            self.controller
                .on_packet_sent(packet.size as u64, packet.time_sent);
        }
        self.outstanding.push_back(packet);
    }

    pub fn on_ack_received(
        &mut self,
        ack: &AckFrame,
        pn_space: PacketNumberSpace,
        now: Instant,
    ) -> (Vec<PacketNumber>, Vec<PacketNumber>) {
        let acked_values = collect_acked_packets(ack);
        let mut acked_packets = Vec::new();
        let mut lost_packets = Vec::new();

        self.loss_time = None;

        for pn_value in acked_values {
            if let Some(position) = self
                .outstanding
                .iter()
                .position(|p| p.packet_number.0 == pn_value && p.packet_number_space == pn_space)
            {
                let packet = self.outstanding.remove(position).unwrap();

                if packet.in_flight {
                    self.controller
                        .on_ack(packet.size as u64, now);
                }

                if packet.ack_eliciting {
                    let sample = now.saturating_duration_since(packet.time_sent);
                    self.update_rtt(sample);
                }

                acked_packets.push(packet.packet_number);
            }
        }

        // Detect time threshold losses.
        let mut pending = VecDeque::new();
        std::mem::swap(&mut pending, &mut self.outstanding);
        while let Some(packet) = pending.pop_front() {
            if packet.packet_number_space != pn_space {
                self.outstanding.push_back(packet);
                continue;
            }

            if self.is_lost(&packet, now) {
                if packet.in_flight {
                    self.controller.on_congestion_event(now);
                }
                lost_packets.push(packet.packet_number);
            } else {
                if packet.in_flight && self.loss_time.is_none() {
                    self.loss_time = Some(packet.time_sent + self.loss_delay());
                }
                self.outstanding.push_back(packet);
            }
        }

        (acked_packets, lost_packets)
    }

    fn is_lost(&self, packet: &SentPacket, now: Instant) -> bool {
        let loss_delay = self.loss_delay();
        now.duration_since(packet.time_sent) >= loss_delay
    }

    fn loss_delay(&self) -> Duration {
        let srtt = self.smoothed_rtt.unwrap_or_else(|| Duration::from_millis(333));
        let latest = self.latest_rtt.unwrap_or(srtt);
        let base = if srtt > latest { srtt } else { latest };
        base + base / 8 // 1.125 * max
    }

    fn update_rtt(&mut self, sample: Duration) {
        self.latest_rtt = Some(sample);
        self.min_rtt = Some(self.min_rtt.map_or(sample, |min| min.min(sample)));

        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.unwrap_or_else(|| srtt / 2);
                let abs = if srtt > sample { srtt - sample } else { sample - srtt };
                let new_rttvar = (3 * rttvar + abs) / 4;
                let new_srtt = (7 * srtt + sample) / 8;
                self.rttvar = Some(new_rttvar);
                self.smoothed_rtt = Some(new_srtt);
            }
        }
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.controller.bytes_in_flight()
    }

    pub fn can_send(&self, datagram_size: usize) -> bool {
        self.controller.can_send(datagram_size)
    }

    pub fn cwnd(&self) -> u64 {
        self.controller.cwnd()
    }
}

fn collect_acked_packets(ack: &AckFrame) -> Vec<u64> {
    let mut acked = Vec::new();
    if ack.ranges.is_empty() {
        acked.push(ack.largest_acknowledged);
        return acked;
    }

    let mut current = ack.largest_acknowledged;
    let mut first = true;

    for AckRange { gap, length } in &ack.ranges {
        if first {
            for pn in current.saturating_sub(*length)..=current {
                acked.push(pn);
            }
            first = false;
        } else {
            current = current.saturating_sub(gap + 1);
            let start = current.saturating_sub(*length);
            for pn in start..=current {
                acked.push(pn);
            }
        }
        current = current.saturating_sub(length + gap + 1);
    }

    acked
}
