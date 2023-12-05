use pyo3::prelude::*;
use pyo3::pyproto::*;
use pyo3::PyIterProtocol;
use bgpkit_parser::{BgpkitParser, BgpElem};
use bgpkit_parser::models::{ElemType, Asn, NetworkPrefix, MetaCommunity, BgpIdentifier, AttrRaw, Community, LargeCommunity, ExtendedCommunity};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[pyclass]
struct PyBgpElem {
    timestamp: f64,
    elem_type: String, // ElemType enum converted to String
    peer_ip: String, // IpAddr converted to String
    peer_asn: u64, // Asn is u64
    prefix: String, // NetworkPrefix needs a custom conversion to String
    next_hop: Option<String>, // Option<IpAddr> converted to Option<String>
    as_path: Option<Vec<u64>>, // Assuming AsPath is Vec<Asn>
    origin_asns: Option<Vec<u64>>, // Assuming Vec<Asn>
    origin: Option<String>, // Origin enum converted to String
    local_pref: Option<u32>,
    med: Option<u32>,
    communities: Option<Vec<String>>, // MetaCommunity enum converted to Vec<String>
    atomic: Option<bool>,
    aggr_asn: Option<u64>, // Asn is u64
    aggr_ip: Option<String>, // BgpIdentifier converted to String
    only_to_customer: Option<u64>, // Asn is u64
    unknown: Option<Vec<(u8, Vec<u8>)>>, // AttrRaw as (u8, Vec<u8>)
    deprecated: Option<Vec<(u8, Vec<u8>)>>, // AttrRaw as (u8, Vec<u8>)
}

#[pymethods]
impl PyBgpElem {
    #[new]
    fn new(
        timestamp: f64,
        elem_type: String,
        peer_ip: String,
        peer_asn: u64,
        prefix: String,
        next_hop: Option<String>,
        as_path: Option<Vec<u64>>,
        origin_asns: Option<Vec<u64>>,
        origin: Option<String>,
        local_pref: Option<u32>,
        med: Option<u32>,
        communities: Option<Vec<String>>,
        atomic: Option<bool>,
        aggr_asn: Option<u64>,
        aggr_ip: Option<String>,
        only_to_customer: Option<u64>,
        unknown: Option<Vec<(u8, Vec<u8>)>>,
        deprecated: Option<Vec<(u8, Vec<u8>)>>,
    ) -> Self {
        PyBgpElem {
            timestamp,
            elem_type,
            peer_ip,
            peer_asn,
            prefix,
            next_hop: None,
            as_path: None,
            origin_asns: None,
            origin: None,
            local_pref: None,
            med: None,
            communities: None,
            atomic: None,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            deprecated: None,
        }
    }
}

#[pyfunction]
fn parse_bgp_data(url: String) -> PyResult<Py<PyBgpElemIterator>> {
    let parser = BgpkitParser::new(&url).unwrap();
    let iter = PyBgpElemIterator { parser };
    Python::with_gil(|py| Ok(Py::new(py, iter)?))
}

struct PyBgpElemIterator {
    parser: BgpkitParser,
}

#[pyproto]
impl PyIterProtocol for PyBgpElemIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<Self>> {
        Ok(slf.into())
    }

    fn __next__(mut slf: PyRefMut<Self>) -> IterNextOutput<PyBgpElem, PyErr> {
        match slf.parser.next() {
            Some(elem) => {
                let communities_str = elem.communities.as_ref().map(|communities| {
                    communities.iter().map(|community| community.to_string()).collect::<Vec<_>>()
                });

                let py_elem = PyBgpElem::new(
                    elem.timestamp,
                    format!("{:?}", elem.elem_type),
                    elem.peer_ip.to_string(),
                    elem.peer_asn, // Assuming Asn is u64
                    elem.prefix.to_string(),
                    elem.next_hop.map(|ip| ip.to_string()),
                    elem.as_path.map(|as_path| as_path.iter().map(|&asn| asn as u64).collect()),
                    elem.origin_asns.map(|origin_asns| origin_asns.iter().map(|&asn| asn as u64).collect()),
                    elem.origin.map(|origin| format!("{:?}", origin)),
                    elem.local_pref,
                    elem.med,
                    communities_str,
                    elem.atomic,
                    elem.aggr_asn,
                    elem.aggr_ip.map(|ip| ip.to_string()),
                    elem.only_to_customer,
                    elem.unknown.map(|unknown| unknown.iter().map(|attr_raw| {
                        let attr_type_str = format!("{:?}", attr_raw.attr_type); // Convert AttrType to String
                        let bytes_str = format!("{:02X?}", attr_raw.bytes); // Convert Vec<u8> to hex string
                        (attr_type_str, bytes_str)
                    }).collect()),
                    elem.deprecated.map(|deprecated| deprecated.iter().map(|&(typ, ref bytes)| (typ, bytes.clone())).collect()),
                );
                IterNextOutput::Yield(Ok(py_elem))
            }
            None => IterNextOutput::Return(Ok(())),
        }
    }
}

#[pymodule]
fn bgpkit_parser_py(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyBgpElem>()?;
    m.add_function(wrap_pyfunction!(parse_bgp_data, m)?)?;
    Ok(())
}
