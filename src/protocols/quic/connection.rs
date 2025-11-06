use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::debug;
use crate::crypto::{tls13_keyschedule::Tls13KeySchedule, Tls13HashAlgorithm, x25519, x25519_public_key};
use crate::protocols::crypto::SecureRandom;

use super::constants::*;
use super::crypto::{derive_initial_keys, derive_packet_keyset, ClientInitialKeys, PacketKeySet, ServerInitialKeys, HEADER_SAMPLE_LEN};
use super::frame::{AckFrame, AckRange, CryptoFrame, Frame, StreamFrame};
use super::packet::{
    parse_packet, ConnectionId, LongHeader, LongPacketType, PacketHeader, PacketNumber,
    PacketNumberSpace, QuicPacket, QuicVersion, ShortHeader,
};
use super::recovery::{LossRecovery, SentPacket};
use super::stream::{
    direction_for_id,
    initiator_from_id,
    stream_id as make_stream_id,
    stream_type_from_id,
    StreamDirection,
    StreamId,
    StreamInitiator,
    StreamType,
    TransportStream,
};

/// QUIC endpoint role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicEndpointType {
    Client,
    Server,
}

/// QUIC configuration parameters for a connection.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub server_name: String,
    pub remote: SocketAddr,
    pub alpn: Vec<String>,
    pub endpoint_type: QuicEndpointType,
    pub max_datagram_size: usize,
    pub idle_timeout: Duration,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
}

impl QuicConfig {
    pub fn client(server_name: String, remote: SocketAddr, alpn: Vec<String>) -> Self {
        Self {
            server_name,
            remote,
            alpn,
            endpoint_type: QuicEndpointType::Client,
            max_datagram_size: MAX_DATAGRAM_SIZE,
            idle_timeout: Duration::from_secs(30),
            initial_max_data: 1 << 20, // 1 MiB
            initial_max_stream_data_bidi: 1 << 16,
            initial_max_stream_data_uni: 1 << 16,
            initial_max_streams_bidi: 16,
            initial_max_streams_uni: 16,
        }
    }
}

/// QUIC connection state.
pub struct QuicConnection {
    config: QuicConfig,
    socket: UdpSocket,
    pub connection_id: ConnectionId,
    pub peer_connection_id: ConnectionId,
    initial_client_keys: ClientInitialKeys,
    initial_server_keys: ServerInitialKeys,
    handshake_client_keys: Option<PacketKeySet>,
    handshake_server_keys: Option<PacketKeySet>,
    application_client_keys: Option<PacketKeySet>,
    application_server_keys: Option<PacketKeySet>,
    loss_recovery: LossRecovery,
    retransmit_buffer: BTreeMap<(PacketNumberSpace, u64), Vec<Frame>>,
    ack_manager: AckManager,
    pn_initial: PacketNumber,
    pn_handshake: PacketNumber,
    pn_application: PacketNumber,
    initial_crypto: Vec<u8>,
    handshake_crypto: Vec<u8>,
    application_crypto: Vec<u8>,
    handshake_transcript: Vec<u8>,
    transport_parameters: Vec<u8>,
    client_private_key: [u8; 32],
    client_public_key: [u8; 32],
    server_public_key: Option<[u8; 32]>,
    streams: BTreeMap<StreamId, TransportStream>,
    incoming_events: Vec<StreamEvent>,
    next_bidi_stream: u64,
    next_uni_stream: u64,
    key_phase: bool,
    peer_transport_parameters: Vec<u8>,
    server_certificate: Option<Vec<u8>>,
    remote_initial_source_connection_id: Option<ConnectionId>,
    connected: bool,
    key_schedule: Tls13KeySchedule,
    server_hello_processed: bool,
}

impl QuicConnection {
    pub fn new(config: QuicConfig) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("failed to bind UDP socket: {}", e))?;
        socket
            .connect(config.remote)
            .map_err(|e| format!("failed to connect UDP socket: {}", e))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| format!("failed to set read timeout: {}", e))?;

        let peer_connection_id = ConnectionId::random(8);
        let connection_id = ConnectionId::random(8);
        let (client_keys, server_keys) = derive_initial_keys(peer_connection_id.as_bytes());

        let mut rng = SecureRandom::new()?;
        let mut client_private_key = [0u8; 32];
        rng.fill_bytes(&mut client_private_key)?;
        let client_public_key = x25519_public_key(&client_private_key);

        let mut conn = Self {
            connection_id,
            peer_connection_id,
            initial_client_keys: client_keys,
            initial_server_keys: server_keys,
            handshake_client_keys: None,
            handshake_server_keys: None,
            application_client_keys: None,
            application_server_keys: None,
            loss_recovery: LossRecovery::new(config.max_datagram_size as u64),
            retransmit_buffer: BTreeMap::new(),
            ack_manager: AckManager::new(),
            pn_initial: PacketNumber::new(0),
            pn_handshake: PacketNumber::new(0),
            pn_application: PacketNumber::new(0),
            initial_crypto: Vec::new(),
            handshake_crypto: Vec::new(),
            application_crypto: Vec::new(),
            handshake_transcript: Vec::new(),
            transport_parameters: Vec::new(),
            client_private_key,
            client_public_key,
            server_public_key: None,
            streams: BTreeMap::new(),
            incoming_events: Vec::new(),
            next_bidi_stream: 0,
            next_uni_stream: 0,
            key_phase: false,
            peer_transport_parameters: Vec::new(),
            server_certificate: None,
            remote_initial_source_connection_id: None,
            socket,
            config,
            connected: false,
            key_schedule: Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256),
            server_hello_processed: false,
        };

        conn.transport_parameters = conn.build_transport_parameters();
        Ok(conn)
    }

    /// Initiate handshake by sending Initial flight.
    pub fn connect(&mut self) -> Result<(), String> {
        if self.config.endpoint_type != QuicEndpointType::Client {
            return Err("server-side handshake not implemented yet".to_string());
        }

        debug!("Building ClientHello for QUIC+TLS handshake");
        let client_hello = self.build_client_hello_payload()?;
        debug!("ClientHello size: {} bytes", client_hello.len());

        // Record transcript for future handshake completion.
        self.handshake_transcript
            .extend_from_slice(&client_hello);
        self.key_schedule.add_to_transcript(&client_hello);

        // Build CRYPTO frame carrying ClientHello.
        let frames = vec![Frame::Crypto(CryptoFrame {
            offset: 0,
            data: client_hello,
        })];

        debug!("Sending QUIC Initial packet to {}:{}",
            self.config.remote.ip(), self.config.remote.port());
        self.send_frames(PacketNumberSpace::Initial, frames, true)
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn send_unidirectional_stream(&mut self, data: &[u8]) -> Result<StreamId, String> {
        if self.application_client_keys.is_none() {
            return Err("application keys not available".to_string());
        }

        let stream_id = make_stream_id(StreamInitiator::Client, StreamType::Unidirectional, self.next_uni_stream);
        self.next_uni_stream = self.next_uni_stream.saturating_add(1);

        self.send_stream_data(stream_id, data.to_vec(), true)?;
        Ok(stream_id)
    }

    pub fn open_bidirectional_stream(&mut self) -> StreamId {
        let stream_id = make_stream_id(StreamInitiator::Client, StreamType::Bidirectional, self.next_bidi_stream);
        self.next_bidi_stream = self.next_bidi_stream.saturating_add(1);
        stream_id
    }

    pub fn send_stream_data(&mut self, stream_id: StreamId, data: Vec<u8>, fin: bool) -> Result<(), String> {
        if self.application_client_keys.is_none() {
            return Err("application keys not available".to_string());
        }

        let frame = Frame::Stream(StreamFrame {
            stream_id,
            offset: 0,
            data,
            fin,
        });

        self.send_frames(PacketNumberSpace::Application, vec![frame], true)
    }

    /// Receive and process a single QUIC datagram from the peer.
    pub fn poll_io(&mut self) -> Result<(), String> {
        let mut buffer = vec![0u8; self.config.max_datagram_size * 2];
        let size = self
            .socket
            .recv(&mut buffer)
            .map_err(|e| format!("failed to receive QUIC datagram: {}", e))?;
        buffer.truncate(size);
        debug!("Received {} byte datagram", size);
        self.handle_datagram(&mut buffer)?;
        Ok(())
    }

    fn register_sent_packet(
        &mut self,
        space: PacketNumberSpace,
        pn: PacketNumber,
        size: usize,
        ack_eliciting: bool,
        frames: Option<Vec<Frame>>,
    ) {
        let packet = SentPacket {
            packet_number: pn,
            packet_number_space: space,
            time_sent: Instant::now(),
            size,
            ack_eliciting,
            in_flight: ack_eliciting,
        };
        self.loss_recovery.on_packet_sent(packet);

        if ack_eliciting {
            if let Some(data) = frames {
                self.retransmit_buffer.insert((space, pn.0), data);
            }
        }
    }

    fn send_frames(
        &mut self,
        space: PacketNumberSpace,
        frames: Vec<Frame>,
        ack_eliciting: bool,
    ) -> Result<(), String> {
        if ack_eliciting && matches!(space, PacketNumberSpace::Handshake | PacketNumberSpace::Application) {
            for frame in &frames {
                if let Frame::Stream(ref sf) = frame {
                    self.prepare_local_stream(sf.stream_id, &sf.data, sf.fin)?;
                }
            }
        }

        let payload = encode_frames(&frames);

        let (header, pn) = match space {
            PacketNumberSpace::Initial => {
                let pn = self.pn_initial;
                let pn_len = pn.encode_len();
                let header = LongHeader {
                    packet_type: LongPacketType::Initial,
                    version: QuicVersion::V1,
                    destination_connection_id: self.peer_connection_id.clone(),
                    source_connection_id: self.connection_id.clone(),
                    token: Vec::new(),
                    payload_length: (payload.len() + pn_len) as u64,
                };
                (PacketHeader::Long(header), pn)
            }
            PacketNumberSpace::Handshake => {
                if self.handshake_client_keys.is_none() {
                    return Err("handshake keys not available".to_string());
                }
                let pn = self.pn_handshake;
                let pn_len = pn.encode_len();
                let header = LongHeader {
                    packet_type: LongPacketType::Handshake,
                    version: QuicVersion::V1,
                    destination_connection_id: self.peer_connection_id.clone(),
                    source_connection_id: self.connection_id.clone(),
                    token: Vec::new(),
                    payload_length: (payload.len() + pn_len) as u64,
                };
                (PacketHeader::Long(header), pn)
            }
            PacketNumberSpace::Application => {
                if self.application_client_keys.is_none() {
                    return Err("application keys not available".to_string());
                }
                let pn = self.pn_application;
                let header = PacketHeader::Short(ShortHeader {
                    destination_connection_id: self.peer_connection_id.clone(),
                    key_phase: self.key_phase,
                    spin_bit: false,
                });
                (header, pn)
            }
        };

        let mut packet = QuicPacket::new(header, pn, payload);
        if matches!(space, PacketNumberSpace::Initial) {
            debug!("Payload before padding: {} bytes", packet.payload.len());
            packet.ensure_initial_minimum();
            debug!("Payload after padding: {} bytes", packet.payload.len());
        }
        if let PacketHeader::Long(ref mut hdr) = packet.header {
            hdr.payload_length = (packet.payload.len() + packet.packet_number_len) as u64;
        }

        let datagram = self.seal_packet(packet, space)?;
        debug!("Sending {:?} packet: {} bytes", space, datagram.len());
        if matches!(space, PacketNumberSpace::Initial) {
            let hex_preview: String = datagram.iter().take(64)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            debug!("Initial packet header (first 64 bytes): {}", hex_preview);
        }
        self.socket
            .send(&datagram)
            .map_err(|e| format!("failed to send QUIC packet: {}", e))?;

        let frames_for_store = if ack_eliciting {
            Some(frames.clone())
        } else {
            None
        };

        self.register_sent_packet(space, pn, datagram.len(), ack_eliciting, frames_for_store);
        match space {
            PacketNumberSpace::Initial => {
                self.pn_initial = PacketNumber::new(self.pn_initial.0 + 1);
            }
            PacketNumberSpace::Handshake => {
                self.pn_handshake = PacketNumber::new(self.pn_handshake.0 + 1);
            }
            PacketNumberSpace::Application => {
                self.pn_application = PacketNumber::new(self.pn_application.0 + 1);
            }
        }

        Ok(())
    }

    fn prepare_local_stream(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<(), String> {
        let stream = self.ensure_stream(stream_id);
        if !data.is_empty() {
            stream.push_send_data(data)?;
        }
        if fin {
            stream.set_fin();
        }
        Ok(())
    }

    fn ensure_stream(&mut self, stream_id: StreamId) -> &mut TransportStream {
        let entry = self.streams.entry(stream_id).or_insert_with(|| {
            let stream_type = stream_type_from_id(stream_id);
            let initiator = initiator_from_id(stream_id);
            let direction = direction_for_id(stream_id, StreamInitiator::Client);
            let initial_budget = match stream_type {
                StreamType::Bidirectional => self.config.initial_max_stream_data_bidi,
                StreamType::Unidirectional => self.config.initial_max_stream_data_uni,
            };
            TransportStream::new(
                stream_id,
                stream_type,
                initiator,
                direction,
                initial_budget,
                initial_budget,
            )
        });
        entry
    }

    fn seal_packet(
        &self,
        mut packet: QuicPacket,
        space: PacketNumberSpace,
    ) -> Result<Vec<u8>, String> {
        let keys = match space {
            PacketNumberSpace::Initial => &self.initial_client_keys.packet,
            PacketNumberSpace::Handshake => self
                .handshake_client_keys
                .as_ref()
                .ok_or_else(|| "handshake keys not available".to_string())?,
            PacketNumberSpace::Application => self
                .application_client_keys
                .as_ref()
                .ok_or_else(|| "application keys not available".to_string())?,
        };

        let encoded_header = packet.encode_header();
        let mut header_bytes = encoded_header.bytes.clone();

        let pn_bytes = packet
            .packet_number
            .to_bytes(packet.packet_number_len);

        for (idx, value) in pn_bytes.iter().enumerate() {
            header_bytes[encoded_header.packet_number_offset + idx] = *value;
        }

        let ciphertext = keys.encrypt(packet.packet_number.0, &header_bytes, &packet.payload);

        let mut datagram = header_bytes.clone();
        datagram.extend_from_slice(&ciphertext);

        let sample_offset = encoded_header.packet_number_offset + packet.packet_number_len;
        if sample_offset + HEADER_SAMPLE_LEN > datagram.len() {
            return Err("packet too short for header protection".to_string());
        }

        // Copy sample to owned array to avoid borrow conflicts
        let mut sample_array = [0u8; HEADER_SAMPLE_LEN];
        sample_array.copy_from_slice(&datagram[sample_offset..sample_offset + HEADER_SAMPLE_LEN]);

        // Apply header protection - manually XOR to avoid overlapping mutable borrows
        let mask = keys.generate_hp_mask(&sample_array);

        // Apply to first byte (long header: lower 4 bits, short: lower 5 bits)
        if (datagram[0] & 0x80) != 0 {
            datagram[0] ^= mask[0] & 0x0f;
        } else {
            datagram[0] ^= mask[0] & 0x1f;
        }

        // Apply to packet number bytes
        let pn_offset = encoded_header.packet_number_offset;
        let pn_len = packet.packet_number_len;
        for i in 0..pn_len {
            datagram[pn_offset + i] ^= mask[1 + i];
        }

        Ok(datagram)
    }

    fn handle_datagram(&mut self, datagram: &mut [u8]) -> Result<(), String> {
        if datagram.is_empty() {
            return Err("empty datagram".to_string());
        }

        let decode = parse_packet(datagram, self.connection_id.len())?;
        let pn_space = match &decode.header {
            PacketHeader::Long(long) => match long.packet_type {
                LongPacketType::Initial => PacketNumberSpace::Initial,
                LongPacketType::Handshake => PacketNumberSpace::Handshake,
                LongPacketType::ZeroRtt => PacketNumberSpace::Application,
                LongPacketType::Retry => {
                    return Err("retry packets are not handled yet".to_string());
                }
            },
            PacketHeader::Short(_) => PacketNumberSpace::Application,
        };

        if let PacketHeader::Long(long) = &decode.header {
            if self.remote_initial_source_connection_id.is_none() {
                self.remote_initial_source_connection_id = Some(long.source_connection_id.clone());
            }
        }

        let keys = match pn_space {
            PacketNumberSpace::Initial => &self.initial_server_keys.packet,
            PacketNumberSpace::Handshake => self
                .handshake_server_keys
                .as_ref()
                .ok_or_else(|| "handshake keys not available".to_string())?,
            PacketNumberSpace::Application => self
                .application_server_keys
                .as_ref()
                .ok_or_else(|| "1-RTT keys not available".to_string())?,
        };

        let sample_start = decode.packet_number_offset + decode.packet_number_length;
        if sample_start + HEADER_SAMPLE_LEN > datagram.len() {
            return Err("datagram too short for header protection sample".to_string());
        }

        // Copy sample to owned array to avoid borrow conflicts
        let mut sample_array = [0u8; HEADER_SAMPLE_LEN];
        sample_array.copy_from_slice(&datagram[sample_start..sample_start + HEADER_SAMPLE_LEN]);

        // Remove header protection - manually XOR to avoid overlapping mutable borrows
        let mask = keys.generate_hp_mask(&sample_array);

        // Apply to first byte (long header: lower 4 bits, short: lower 5 bits)
        if (datagram[0] & 0x80) != 0 {
            datagram[0] ^= mask[0] & 0x0f;
        } else {
            datagram[0] ^= mask[0] & 0x1f;
        }

        // Apply to packet number bytes
        let pn_offset = decode.packet_number_offset;
        let pn_len = decode.packet_number_length;
        for i in 0..pn_len {
            datagram[pn_offset + i] ^= mask[1 + i];
        }

        let pn_bytes = &datagram[decode.packet_number_offset
            ..decode.packet_number_offset + decode.packet_number_length];
        let mut packet_number_value = 0u64;
        for byte in pn_bytes {
            packet_number_value = (packet_number_value << 8) | (*byte as u64);
        }
        let packet_number = PacketNumber::new(packet_number_value);

        let aad = &datagram[..decode.payload_offset];
        let ciphertext = &datagram[decode.payload_offset..];
        let plaintext = keys.decrypt(packet_number.0, aad, ciphertext)?;

        let mut cursor = 0usize;
        let mut ack_eliciting = false;
        while cursor < plaintext.len() {
            let frame = Frame::decode(&plaintext, &mut cursor)?;
            if !matches!(frame, Frame::Ack(_)) {
                ack_eliciting = true;
            }
            self.handle_frame(pn_space, frame)?;
        }

        if ack_eliciting {
            self.queue_ack(pn_space, packet_number);
            self.flush_pending_ack(pn_space)?;
        }

        Ok(())
    }

    fn handle_frame(
        &mut self,
        space: PacketNumberSpace,
        frame: Frame,
    ) -> Result<(), String> {
        match frame {
            Frame::Ack(ref ack) => {
                let now = Instant::now();
                let (acked, lost) = self
                    .loss_recovery
                    .on_ack_received(ack, space, now);
                self.on_packets_acked(space, &acked);
                self.on_packets_lost(space, lost, now)?;
            }
            Frame::Crypto(crypto) => {
                self.handle_crypto_frame(space, &crypto)?;
            }
            Frame::Stream(stream_frame) => {
                self.handle_stream_frame(space, stream_frame)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_crypto_frame(
        &mut self,
        space: PacketNumberSpace,
        frame: &CryptoFrame,
    ) -> Result<(), String> {
        match space {
            PacketNumberSpace::Initial => {
                append_crypto(&mut self.initial_crypto, frame)?;
                if frame.offset as usize == self.handshake_transcript.len() {
                    self.handshake_transcript.extend_from_slice(&frame.data);
                }
                self.process_initial_crypto()?;
            }
            PacketNumberSpace::Handshake => {
                append_crypto(&mut self.handshake_crypto, frame)?;
                self.process_handshake_crypto()?;
            }
            PacketNumberSpace::Application => {
                append_crypto(&mut self.application_crypto, frame)?;
            }
        }

        Ok(())
    }

    fn handle_stream_frame(
        &mut self,
        space: PacketNumberSpace,
        frame: StreamFrame,
    ) -> Result<(), String> {
        if !matches!(space, PacketNumberSpace::Application) {
            return Ok(());
        }

        let fin = frame.fin;
        let stream_id = frame.stream_id;
        let stream = self.ensure_stream(stream_id);
        stream.on_stream_frame(&frame)?;

        let mut data = stream.read_available();
        if !data.is_empty() || fin {
            self.incoming_events.push(StreamEvent { stream_id, data, fin });
        }

        Ok(())
    }

    fn process_initial_crypto(&mut self) -> Result<(), String> {
        if self.server_hello_processed {
            return Ok(());
        }

        if self.initial_crypto.len() < 4 {
            return Ok(());
        }

        let total_len = 4
            + ((self.initial_crypto[1] as usize) << 16)
            + ((self.initial_crypto[2] as usize) << 8)
            + (self.initial_crypto[3] as usize);

        if self.initial_crypto.len() < total_len {
            return Ok(());
        }

        let message = self.initial_crypto[..total_len].to_vec();
        let ParsedServerHello {
            server_public_key,
            ..
        } = parse_server_hello(&message)?;

        self.server_public_key = Some(server_public_key);

        self.key_schedule.add_to_transcript(&message);

        let shared_secret = x25519(&self.client_private_key, &server_public_key);
        self.handshake_transcript.extend_from_slice(&message);

        self.key_schedule.derive_handshake_secret(&shared_secret);
        self.key_schedule.derive_handshake_traffic_secrets();

        let client_secret = self
            .key_schedule
            .client_handshake_traffic_secret
            .clone()
            .ok_or_else(|| "missing client handshake traffic secret".to_string())?;
        let server_secret = self
            .key_schedule
            .server_handshake_traffic_secret
            .clone()
            .ok_or_else(|| "missing server handshake traffic secret".to_string())?;

        let client_secret_array: [u8; 32] = client_secret
            .as_slice()
            .try_into()
            .map_err(|_| "client handshake secret must be 32 bytes".to_string())?;
        let server_secret_array: [u8; 32] = server_secret
            .as_slice()
            .try_into()
            .map_err(|_| "server handshake secret must be 32 bytes".to_string())?;

        self.handshake_client_keys = Some(derive_packet_keyset(&client_secret_array));
        self.handshake_server_keys = Some(derive_packet_keyset(&server_secret_array));

        self.server_hello_processed = true;
        self.initial_crypto.drain(..total_len);

        self.flush_pending_ack(PacketNumberSpace::Handshake)?;

        Ok(())
    }

    fn process_handshake_crypto(&mut self) -> Result<(), String> {
        loop {
            if self.handshake_crypto.len() < 4 {
                return Ok(());
            }

            let length = ((self.handshake_crypto[1] as usize) << 16)
                | ((self.handshake_crypto[2] as usize) << 8)
                | (self.handshake_crypto[3] as usize);

            if self.handshake_crypto.len() < 4 + length {
                return Ok(());
            }

            let message = self.handshake_crypto[..4 + length].to_vec();
            self.handshake_crypto.drain(..4 + length);

            self.handshake_transcript.extend_from_slice(&message);
            self.key_schedule.add_to_transcript(&message);

            let handshake_type = message[0];
            let body = &message[4..];
            self.handle_handshake_message(handshake_type, body)?;
        }
    }

    fn queue_ack(&mut self, space: PacketNumberSpace, packet_number: PacketNumber) {
        if matches!(space, PacketNumberSpace::Application) {
            return;
        }
        self.ack_manager.on_packet_received(space, packet_number);
    }

    fn on_packets_acked(&mut self, space: PacketNumberSpace, acked: &[PacketNumber]) {
        for pn in acked {
            self.retransmit_buffer.remove(&(space, pn.0));
        }
    }

    fn on_packets_lost(
        &mut self,
        space: PacketNumberSpace,
        lost: Vec<PacketNumber>,
        _now: Instant,
    ) -> Result<(), String> {
        for pn in lost {
            if let Some(frames) = self.retransmit_buffer.remove(&(space, pn.0)) {
                self.send_frames(space, frames, true)?;
            }
        }
        Ok(())
    }

    fn flush_pending_ack(&mut self, space: PacketNumberSpace) -> Result<(), String> {
        if !matches!(space, PacketNumberSpace::Initial | PacketNumberSpace::Handshake) {
            return Ok(());
        }

        if matches!(space, PacketNumberSpace::Handshake) && self.handshake_client_keys.is_none() {
            return Ok(());
        }

        if !self.ack_manager.has_pending(space) {
            return Ok(());
        }

        let ack_frame = match self.ack_manager.build_ack(space, 0) {
            Some(frame) => frame,
            None => return Ok(()),
        };

        self.send_frames(space, vec![Frame::Ack(ack_frame)], false)?;
        self.ack_manager.clear(space);

        Ok(())
    }

    fn handle_handshake_message(&mut self, handshake_type: u8, body: &[u8]) -> Result<(), String> {
        match handshake_type {
            0x08 => self.handle_encrypted_extensions(body)?,
            0x11 => {
                if let Some(cert) = parse_certificate_message(body)? {
                    self.server_certificate = Some(cert);
                }
            }
            0x14 => self.handle_server_finished(body)?,
            _ => {}
        }
        Ok(())
    }

    fn handle_encrypted_extensions(&mut self, body: &[u8]) -> Result<(), String> {
        if body.len() < 2 {
            return Err("encrypted extensions truncated".to_string());
        }
        let mut cursor = 0usize;
        let ext_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
        cursor += 2;
        if cursor + ext_len > body.len() {
            return Err("encrypted extensions length mismatch".to_string());
        }

        let mut ext_cursor = cursor;
        let ext_end = cursor + ext_len;

        while ext_cursor < ext_end {
            if ext_cursor + 4 > ext_end {
                return Err("encrypted extensions malformed header".to_string());
            }
            let ext_type = u16::from_be_bytes([body[ext_cursor], body[ext_cursor + 1]]);
            let ext_size = u16::from_be_bytes([body[ext_cursor + 2], body[ext_cursor + 3]]) as usize;
            ext_cursor += 4;
            if ext_cursor + ext_size > ext_end {
                return Err("encrypted extensions truncated entry".to_string());
            }
            let ext_data = &body[ext_cursor..ext_cursor + ext_size];
            ext_cursor += ext_size;

            if ext_type == 0x0039 {
                self.peer_transport_parameters = ext_data.to_vec();
            }
        }

        Ok(())
    }

    fn handle_server_finished(&mut self, _body: &[u8]) -> Result<(), String> {
        if self.application_server_keys.is_some() {
            return Ok(());
        }

        self.key_schedule.derive_master_secret();
        self.key_schedule.derive_application_traffic_secrets();

        let client_secret = self
            .key_schedule
            .client_application_traffic_secret
            .clone()
            .ok_or_else(|| "missing client application traffic secret".to_string())?;
        let server_secret = self
            .key_schedule
            .server_application_traffic_secret
            .clone()
            .ok_or_else(|| "missing server application traffic secret".to_string())?;

        let client_secret_array: [u8; 32] = client_secret
            .as_slice()
            .try_into()
            .map_err(|_| "client application secret must be 32 bytes".to_string())?;
        let server_secret_array: [u8; 32] = server_secret
            .as_slice()
            .try_into()
            .map_err(|_| "server application secret must be 32 bytes".to_string())?;

        self.application_client_keys = Some(derive_packet_keyset(&client_secret_array));
        self.application_server_keys = Some(derive_packet_keyset(&server_secret_array));
        self.connected = true;

        Ok(())
    }

    fn build_client_hello_payload(&self) -> Result<Vec<u8>, String> {
        let mut client_random = [0u8; 32];
        let mut rng = SecureRandom::new()?;
        rng.fill_bytes(&mut client_random)?;

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        hello.extend_from_slice(&client_random);
        hello.push(0); // empty session id

        // Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
        hello.push(0x00);
        hello.push(0x06);
        hello.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);

        hello.push(1);
        hello.push(0); // compression methods

        let extensions = self.build_client_extensions()?;
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        Ok(handshake)
    }

    fn build_client_extensions(&self) -> Result<Vec<u8>, String> {
        let mut extensions = Vec::new();

        // SNI
        {
            let mut server_name_list = Vec::new();
            server_name_list.push(0x00);
            server_name_list.extend_from_slice(&(self.config.server_name.len() as u16).to_be_bytes());
            server_name_list.extend_from_slice(self.config.server_name.as_bytes());

            let mut sni = Vec::new();
            sni.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
            sni.extend_from_slice(&server_name_list);

            push_extension(&mut extensions, 0x0000, &sni);
        }

        // Supported Versions (TLS 1.3)
        push_extension(&mut extensions, 0x002b, &[0x02, 0x03, 0x04]);

        // Supported Groups (x25519)
        push_extension(&mut extensions, 0x000a, &[0x00, 0x02, 0x00, 0x1d]);

        // Signature Algorithms
        push_extension(
            &mut extensions,
            0x000d,
            &[0x00, 0x08, 0x04, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09],
        );

        // Key Share
        push_extension(&mut extensions, 0x0033, &self.build_key_share_extension());

        // PSK key exchange modes (only psk_dhe_ke)
        push_extension(&mut extensions, 0x002d, &[0x01, 0x01]);

        // ALPN
        if !self.config.alpn.is_empty() {
            push_extension(&mut extensions, 0x0010, &self.build_alpn_extension());
        }

        // QUIC transport parameters
        let mut transport_data = Vec::new();
        transport_data.extend_from_slice(&(self.transport_parameters.len() as u16).to_be_bytes());
        transport_data.extend_from_slice(&self.transport_parameters);
        push_extension(&mut extensions, 0x0039, &transport_data);

        Ok(extensions)
    }

    fn build_key_share_extension(&self) -> Vec<u8> {
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&[0x00, 0x1d]);
        key_share.extend_from_slice(&(self.client_public_key.len() as u16).to_be_bytes());
        key_share.extend_from_slice(&self.client_public_key);

        let mut body = Vec::new();
        body.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
        body.extend_from_slice(&key_share);
        body
    }

    fn build_alpn_extension(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        for proto in &self.config.alpn {
            inner.push(proto.len() as u8);
            inner.extend_from_slice(proto.as_bytes());
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        payload.extend_from_slice(&inner);
        payload
    }

    fn build_transport_parameters(&self) -> Vec<u8> {
        let mut params = Vec::new();

        // RFC 9000 Section 7.3: original_destination_connection_id is REQUIRED for clients
        push_transport_param(
            &mut params,
            TP_ORIGINAL_DESTINATION_CONNECTION_ID,
            self.peer_connection_id.as_bytes(),
        );

        debug!("Transport param TP_ORIGINAL_DESTINATION_CONNECTION_ID (0x{:04x}): {} bytes",
            TP_ORIGINAL_DESTINATION_CONNECTION_ID,
            self.peer_connection_id.as_bytes().len());

        push_transport_param(
            &mut params,
            TP_MAX_IDLE_TIMEOUT,
            &varint_bytes(self.config.idle_timeout.as_millis() as u64),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_DATA,
            &varint_bytes(self.config.initial_max_data),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            &varint_bytes(self.config.initial_max_stream_data_bidi),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            &varint_bytes(self.config.initial_max_stream_data_bidi),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            &varint_bytes(self.config.initial_max_stream_data_uni),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_STREAMS_BIDI,
            &varint_bytes(self.config.initial_max_streams_bidi),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_MAX_STREAMS_UNI,
            &varint_bytes(self.config.initial_max_streams_uni),
        );
        push_transport_param(
            &mut params,
            TP_ACK_DELAY_EXPONENT,
            &varint_bytes(DEFAULT_ACK_DELAY_EXPONENT as u64),
        );
        push_transport_param(
            &mut params,
            TP_MAX_ACK_DELAY,
            &varint_bytes(DEFAULT_MAX_ACK_DELAY as u64),
        );
        push_transport_param(
            &mut params,
            TP_INITIAL_SOURCE_CONNECTION_ID,
            self.connection_id.as_bytes(),
        );

        debug!("Total transport parameters: {} bytes", params.len());
        if params.len() < 200 {
            let hex: String = params.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            debug!("Transport parameters hex: {}", hex);
        }

        params
    }
}

fn push_extension(target: &mut Vec<u8>, extension_type: u16, data: &[u8]) {
    target.extend_from_slice(&extension_type.to_be_bytes());
    target.extend_from_slice(&(data.len() as u16).to_be_bytes());
    target.extend_from_slice(data);
}

fn push_transport_param(target: &mut Vec<u8>, identifier: u64, value: &[u8]) {
    target.extend_from_slice(&varint_bytes(identifier));
    target.extend_from_slice(&varint_bytes(value.len() as u64));
    target.extend_from_slice(value);
}

fn varint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    super::packet::encode_varint(value, &mut out);
    out
}

fn append_crypto(target: &mut Vec<u8>, frame: &CryptoFrame) -> Result<(), String> {
    let offset = frame.offset as usize;
    let end = offset
        .checked_add(frame.data.len())
        .ok_or_else(|| "crypto frame length overflow".to_string())?;

    if target.len() < end {
        target.resize(end, 0u8);
    }

    target[offset..end].copy_from_slice(&frame.data);
    Ok(())
}

struct ParsedServerHello {
    cipher_suite: u16,
    random: [u8; 32],
    server_public_key: [u8; 32],
}

struct AckEntry {
    received: BTreeSet<u64>,
}

struct AckManager {
    initial: AckEntry,
    handshake: AckEntry,
    application: AckEntry,
}

impl AckEntry {
    fn new() -> Self {
        Self {
            received: BTreeSet::new(),
        }
    }

    fn on_packet(&mut self, pn: PacketNumber) {
        self.received.insert(pn.0);
    }

    fn on_loss(&mut self, _pn: PacketNumber) {}

    fn build_ack(&self, ack_delay: u64) -> Option<AckFrame> {
        if self.received.is_empty() {
            return None;
        }

        let mut values: Vec<u64> = self.received.iter().copied().collect();
        values.sort_unstable();
        let mut blocks: Vec<(u64, u64)> = Vec::new();
        let mut current_start = *values.last().unwrap();
        let mut current_end = current_start;

        for pn in values.into_iter().rev().skip(1) {
            if pn + 1 == current_start {
                current_start = pn;
            } else {
                blocks.push((current_start, current_end));
                current_start = pn;
                current_end = pn;
            }
        }
        blocks.push((current_start, current_end));
        blocks.sort_by(|a, b| b.1.cmp(&a.1));

        let mut ranges = Vec::new();
        let mut blocks_iter = blocks.into_iter();
        let first = blocks_iter.next().unwrap();
        let mut prev_start = first.0;

        ranges.push(AckRange {
            gap: 0,
            length: first.1 - first.0,
        });

        for (start, end) in blocks_iter {
            let length = end - start;
            let gap = prev_start.saturating_sub(end.saturating_add(2));
            ranges.push(AckRange { gap, length });
            prev_start = start;
        }

        Some(AckFrame {
            largest_acknowledged: first.1,
            ack_delay,
            ranges,
        })
    }

    fn clear(&mut self) {
        self.received.clear();
    }
}

impl AckManager {
    fn new() -> Self {
        Self {
            initial: AckEntry::new(),
            handshake: AckEntry::new(),
            application: AckEntry::new(),
        }
    }

    fn entry_mut(&mut self, space: PacketNumberSpace) -> &mut AckEntry {
        match space {
            PacketNumberSpace::Initial => &mut self.initial,
            PacketNumberSpace::Handshake => &mut self.handshake,
            PacketNumberSpace::Application => &mut self.application,
        }
    }

    fn entry(&self, space: PacketNumberSpace) -> &AckEntry {
        match space {
            PacketNumberSpace::Initial => &self.initial,
            PacketNumberSpace::Handshake => &self.handshake,
            PacketNumberSpace::Application => &self.application,
        }
    }

    fn on_packet_received(&mut self, space: PacketNumberSpace, pn: PacketNumber) {
        self.entry_mut(space).on_packet(pn);
    }

    fn on_packet_lost(&mut self, _space: PacketNumberSpace, _pn: PacketNumber) {}

    fn build_ack(&self, space: PacketNumberSpace, ack_delay: u64) -> Option<AckFrame> {
        self.entry(space).build_ack(ack_delay)
    }

    fn clear(&mut self, space: PacketNumberSpace) {
        self.entry_mut(space).clear();
    }

    fn has_pending(&self, space: PacketNumberSpace) -> bool {
        !self.entry(space).received.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct StreamEvent {
    pub stream_id: StreamId,
    pub data: Vec<u8>,
    pub fin: bool,
}

impl QuicConnection {
    pub fn take_stream_events(&mut self) -> Vec<StreamEvent> {
        std::mem::take(&mut self.incoming_events)
    }
}

fn parse_server_hello(message: &[u8]) -> Result<ParsedServerHello, String> {
    if message.len() < 4 {
        return Err("server hello truncated".to_string());
    }
    if message[0] != 0x02 {
        return Err(format!("expected ServerHello, found handshake type 0x{:02x}", message[0]));
    }
    let length = ((message[1] as usize) << 16)
        | ((message[2] as usize) << 8)
        | (message[3] as usize);
    if message.len() < 4 + length {
        return Err("server hello length mismatch".to_string());
    }
    let body = &message[4..4 + length];
    let mut cursor = 0usize;

    if cursor + 2 > body.len() {
        return Err("server hello missing legacy_version".to_string());
    }
    let _legacy_version = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
    cursor += 2;

    if cursor + 32 > body.len() {
        return Err("server hello missing random".to_string());
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[cursor..cursor + 32]);
    cursor += 32;

    if cursor >= body.len() {
        return Err("server hello missing session id length".to_string());
    }
    let session_id_len = body[cursor] as usize;
    cursor += 1;
    if cursor + session_id_len > body.len() {
        return Err("server hello truncated session id".to_string());
    }
    cursor += session_id_len;

    if cursor + 2 > body.len() {
        return Err("server hello missing cipher suite".to_string());
    }
    let cipher_suite = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
    cursor += 2;
    if cipher_suite != 0x1301 {
        return Err(format!("unsupported cipher suite 0x{:04x}", cipher_suite));
    }

    if cursor >= body.len() {
        return Err("server hello missing compression method".to_string());
    }
    let compression = body[cursor];
    cursor += 1;
    if compression != 0 {
        return Err("server hello uses unsupported compression".to_string());
    }

    if cursor + 2 > body.len() {
        return Err("server hello missing extensions length".to_string());
    }
    let ext_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + ext_len > body.len() {
        return Err("server hello truncated extensions".to_string());
    }

    let mut ext_cursor = cursor;
    let ext_end = cursor + ext_len;
    let mut supported_versions_valid = false;
    let mut server_public_key: Option<[u8; 32]> = None;

    while ext_cursor < ext_end {
        if ext_cursor + 4 > ext_end {
            return Err("server hello malformed extension header".to_string());
        }
        let ext_type = u16::from_be_bytes([body[ext_cursor], body[ext_cursor + 1]]);
        let ext_size = u16::from_be_bytes([body[ext_cursor + 2], body[ext_cursor + 3]]) as usize;
        ext_cursor += 4;
        if ext_cursor + ext_size > ext_end {
            return Err("server hello truncated extension".to_string());
        }
        let ext_data = &body[ext_cursor..ext_cursor + ext_size];
        ext_cursor += ext_size;

        match ext_type {
            0x002b => {
                // supported_versions
                if ext_data.len() != 2 || ext_data != [0x03, 0x04] {
                    return Err("server hello unsupported TLS version".to_string());
                }
                supported_versions_valid = true;
            }
            0x0033 => {
                // key_share
                if ext_data.len() < 4 {
                    return Err("server hello key_share too short".to_string());
                }
                let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                if group != 0x001d {
                    return Err(format!("server hello unsupported key share group 0x{:04x}", group));
                }
                let kx_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                if ext_data.len() != 4 + kx_len || kx_len != 32 {
                    return Err("server hello key_share length mismatch".to_string());
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&ext_data[4..]);
                server_public_key = Some(key);
            }
            _ => {}
        }
    }

    let server_public_key = server_public_key.ok_or_else(|| "server hello missing key share".to_string())?;
    if !supported_versions_valid {
        return Err("server hello missing supported_versions".to_string());
    }

    Ok(ParsedServerHello {
        cipher_suite,
        random,
        server_public_key,
    })
}

fn parse_certificate_message(body: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if body.is_empty() {
        return Err("certificate message truncated".to_string());
    }
    let context_len = body[0] as usize;
    if 1 + context_len > body.len() {
        return Err("certificate context truncated".to_string());
    }
    let mut cursor = 1 + context_len;
    if cursor + 3 > body.len() {
        return Err("certificate list length missing".to_string());
    }
    let list_len = ((body[cursor] as usize) << 16)
        | ((body[cursor + 1] as usize) << 8)
        | (body[cursor + 2] as usize);
    cursor += 3;
    if cursor + list_len > body.len() {
        return Err("certificate list truncated".to_string());
    }
    if list_len == 0 {
        return Ok(None);
    }

    if cursor + 3 > body.len() {
        return Err("certificate entry length missing".to_string());
    }
    let entry_len = ((body[cursor] as usize) << 16)
        | ((body[cursor + 1] as usize) << 8)
        | (body[cursor + 2] as usize);
    cursor += 3;
    if cursor + entry_len > body.len() {
        return Err("certificate entry truncated".to_string());
    }
    let certificate = body[cursor..cursor + entry_len].to_vec();
    cursor += entry_len;
    if cursor + 2 > body.len() {
        return Err("certificate extensions length missing".to_string());
    }
    let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + extensions_len > body.len() {
        return Err("certificate extensions truncated".to_string());
    }

    Ok(Some(certificate))
}

fn encode_frames(frames: &[Frame]) -> Vec<u8> {
    let mut payload = Vec::new();
    for frame in frames {
        frame.encode(&mut payload);
    }
    payload
}
