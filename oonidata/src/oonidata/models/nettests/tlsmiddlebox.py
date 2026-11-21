from dataclasses import dataclass
from typing import List, Optional

from ...compat import add_slots

from ..dataformats import (
    BaseTestKeys,
    TCPConnect,
    TLSHandshake,
    DNSQuery,
)

from ..base import BaseModel
from ..nettests.base_measurement import BaseMeasurement

@add_slots
@dataclass
class Quote(BaseModel):
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_sequence_number: Optional[int] = None
    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None
    remaining_payload: Optional[str] = None

@add_slots
@dataclass
class ICMPError(BaseModel):
    timeout: Optional[bool] = None
    connected: Optional[bool] = None
    error: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip_country_code: Optional[str] = None
    source_ip_asn: Optional[str] = None
    source_ip_asn_org: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    quote: Optional[Quote] = None
    t0: Optional[float]= None
    t: Optional[float] = None

@add_slots
@dataclass
class ControlTargetTrace(BaseModel):
    ttl: Optional[int] = None
    handshake: Optional[TLSHandshake] = None

@add_slots
@dataclass
class TCPTraceroute(BaseModel):
    ttl: Optional[int] = None
    icmp_error: Optional[ICMPError] = None

@add_slots
@dataclass
class ControlTargetTraceGroup(BaseModel):
    iterations: Optional[List[ControlTargetTrace]] = None
    server_name: Optional[str] = None

@add_slots
@dataclass
class TCPTracerouteGroup(BaseModel):
    iterations: Optional[List[TCPTraceroute]] = None
    server_name: Optional[str] = None

@add_slots
@dataclass
class Trace(BaseModel):
    address: Optional[str] = None
    tcp_traceroute: Optional[TCPTracerouteGroup] = None
    control_trace: Optional[ControlTargetTraceGroup] = None
    target_trace: Optional[ControlTargetTraceGroup] = None

@add_slots
@dataclass
class TLSMiddleboxTestKeys(BaseTestKeys):
    queries: Optional[List[DNSQuery]] = None
    tcp_connect: Optional[List[TCPConnect]] = None
    iterative_trace: Optional[List[Trace]] = None

@add_slots
@dataclass
class TLSMiddlebox(BaseMeasurement):
    __test_name__ = "tlsmiddlebox"

    test_keys: TLSMiddleboxTestKeys
