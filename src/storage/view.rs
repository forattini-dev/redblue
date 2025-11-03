use std::fs;
use std::io::{self, Cursor};
use std::path::Path;

use crate::storage::encoding::DecodeError;
use crate::storage::layout::{FileHeader, SectionEntry, SegmentKind};
use crate::storage::segments::dns::DnsSegmentView;
use crate::storage::segments::hosts::HostSegmentView;
use crate::storage::segments::http::HttpSegmentView;
use crate::storage::segments::ports::PortSegmentView;
use crate::storage::segments::subdomains::SubdomainSegmentView;
use crate::storage::segments::tls::TlsSegmentView;
use crate::storage::segments::whois::WhoisSegmentView;

pub struct RedDbView {
    subdomains: Option<SubdomainSegmentView>,
    ports: Option<PortSegmentView>,
    dns: Option<DnsSegmentView>,
    http: Option<HttpSegmentView>,
    tls: Option<TlsSegmentView>,
    whois: Option<WhoisSegmentView>,
    hosts: Option<HostSegmentView>,
}

impl RedDbView {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let data = fs::read(path)?;
        if data.len() < FileHeader::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rdb file too small",
            ));
        }

        let header = FileHeader::read(Cursor::new(&data)).map_err(decode_err_to_io)?;
        let dir_start = header.directory_offset as usize;
        let dir_len = header.section_count as usize * SectionEntry::SIZE;
        if dir_start + dir_len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rdb directory out of bounds",
            ));
        }

        let directory = SectionEntry::read_all(
            &data[dir_start..dir_start + dir_len],
            header.section_count as usize,
        )
        .map_err(decode_err_to_io)?;

        let mut subdomains = None;
        let mut ports = None;
        let mut dns = None;
        let mut http = None;
        let mut tls = None;
        let mut whois = None;
        let mut hosts_view = None;

        for entry in directory {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;
            if end > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment out of bounds",
                ));
            }
            let segment_bytes = &data[start..end];
            match entry.kind {
                SegmentKind::Subdomains => {
                    let view = SubdomainSegmentView::from_bytes(segment_bytes)
                        .map_err(decode_err_to_io)?;
                    subdomains = Some(view);
                }
                SegmentKind::Ports => {
                    let view =
                        PortSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    ports = Some(view);
                }
                SegmentKind::Dns => {
                    let view =
                        DnsSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    dns = Some(view);
                }
                SegmentKind::Http => {
                    let view =
                        HttpSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    http = Some(view);
                }
                SegmentKind::Tls => {
                    let view =
                        TlsSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    tls = Some(view);
                }
                SegmentKind::Host => {
                    let view =
                        HostSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    hosts_view = Some(view);
                }
                SegmentKind::Whois => {
                    let view =
                        WhoisSegmentView::from_bytes(segment_bytes).map_err(decode_err_to_io)?;
                    whois = Some(view);
                }
                _ => {}
            }
        }

        Ok(Self {
            subdomains,
            ports,
            dns,
            http,
            tls,
            whois,
            hosts: hosts_view,
        })
    }

    pub fn subdomains(&self) -> Option<&SubdomainSegmentView> {
        self.subdomains.as_ref()
    }

    pub fn ports(&self) -> Option<&PortSegmentView> {
        self.ports.as_ref()
    }

    pub fn dns(&self) -> Option<&DnsSegmentView> {
        self.dns.as_ref()
    }

    pub fn http(&self) -> Option<&HttpSegmentView> {
        self.http.as_ref()
    }

    pub fn tls(&self) -> Option<&TlsSegmentView> {
        self.tls.as_ref()
    }

    pub fn whois(&self) -> Option<&WhoisSegmentView> {
        self.whois.as_ref()
    }

    pub fn hosts(&self) -> Option<&HostSegmentView> {
        self.hosts.as_ref()
    }
}

fn decode_err_to_io(err: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.0)
}
