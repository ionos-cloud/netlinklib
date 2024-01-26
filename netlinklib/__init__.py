""" Netlink dump implementation replacement for pyroute2 """

from os import getpid
from socket import AF_NETLINK, AF_UNSPEC, NETLINK_ROUTE, SOCK_RAW, socket
from struct import pack, unpack
from sys import byteorder
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from ipaddress import IPv4Address, IPv6Address, ip_address

from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import

__all__ = ("NllDumpInterrupted", "NllError", "nll_get_links", "nll_get_routes")


class NllError(BaseException):
    pass


class NllDumpInterrupted(NllError):
    pass


def _messages(sk: socket) -> Iterable[Tuple[int, int, int, int, bytes]]:
    """Iterator to return sequence of nl messages read from the socket"""
    buf = b""
    while True:
        if len(buf) < 16:
            buf += sk.recv(8192)
        if not buf:
            return
        datasize = len(buf)
        if datasize < 16:
            raise NllError(f"Short read {datasize}: {buf.hex()}")
        msg_len, msg_type, flags, seq, pid = unpack("=LHHLL", buf[:16])
        if datasize < msg_len:
            raise NllError(
                f"data size {datasize} less then msg_len {msg_len}:"
                f" {buf.hex()}"
            )
        if msg_type == NLMSG_DONE:
            return
        message = buf[16:msg_len]
        buf = buf[msg_len:]
        yield (msg_type, flags, seq, pid, message)


Rtype = TypeVar("Rtype")


def _nll_get_dump(
    s: socket,
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    parser: Callable[[bytes], Rtype],
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    pid = getpid()
    seq = 1
    flags = NLM_F_REQUEST | NLM_F_DUMP
    size = 4 + 2 + 2 + 4 + 4 + len(rtgenmsg)
    nlhdr = pack("=IHHII", size, typ, flags, seq, pid)
    try:
        rc = s.sendto(nlhdr + rtgenmsg, (0, 0))
    except OSError as e:
        raise NllError(e) from e
    if rc < 0:
        raise NllError(f"netlink send rc={rc}")
    dump_interrupted = False
    for msg_type, flags, seq, pid, message in _messages(s):
        if msg_type == NLMSG_NOOP:
            # print("no-op")
            continue
        if msg_type == NLMSG_ERROR:
            raise NllError(f"NLMSG_ERROR {flags} {seq} {pid}: {message.hex()}")
        if msg_type != rtyp:
            raise NllError(f"{msg_type} is not {rtyp}: {message.hex()}")
        if flags & NLM_F_DUMP_INTR:
            dump_interrupted = True  # and continue reading
        yield parser(message, **kwargs)
    if dump_interrupted:
        raise NllDumpInterrupted  # raise this instead of StopIteration


def nll_get_dump(
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    parser: Callable[[bytes], Rtype],
    sk: Optional[socket] = None,
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            for x in _nll_get_dump(
                owns, typ, rtyp, rtgenmsg, parser, **kwargs
            ):
                yield x
            return None  # solely to make pylint happy
    else:
        return _nll_get_dump(sk, typ, rtyp, rtgenmsg, parser, **kwargs)


#######################################################################


Accum = TypeVar("Accum")

RtaDesc = Dict[int, Tuple[Callable[..., Any], Any]]


def to_str(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    accum[key] = data.rstrip(b"\0").decode("ascii")
    return accum


def to_int(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    accum[key] = int.from_bytes(data, byteorder=byteorder)
    return accum


def to_ipaddr(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    size = len(data)
    address: Union[IPv4Address, IPv6Address]
    if size == 4:
        address = IPv4Address(int.from_bytes(data, byteorder="big"))
    elif size == 16:
        address = IPv6Address(int.from_bytes(data, byteorder="big"))
    else:
        # this is potentially less reliable, ints < 2**32 become IPv4
        address = ip_address(int.from_bytes(data, byteorder="big"))
    accum[key] = str(address)
    return accum


def parse_rtalist(accum: Accum, data: bytes, sel: RtaDesc) -> Accum:
    while data:
        if len(data) < 4:
            raise NllError(f"data len {len(data)} < 4: {data.hex()}")
        rta_len, rta_type = unpack("=HH", data[:4])
        if rta_len < 4:
            raise NllError(f"rta_len {rta_len} < 4: {data.hex()}")
        rta_data = data[4:rta_len]
        increment = (rta_len + 4 - 1) & ~(4 - 1)
        if len(data) < increment:
            raise NllError(f"data len {len(data)} < {increment}: {data.hex()}")
        data = data[increment:]
        if rta_type in sel:
            op, *args = sel[rta_type]
            accum = op(accum, rta_data, *args)
    return accum


############################################################

IFF_UP = 1


def parse_rtalist_if_vrf(
    accum: Dict[str, Union[int, str]], data: bytes, sel: RtaDesc
) -> Dict[str, Union[int, str]]:
    """Parse KRT only if kind == vrf has been already put into accum"""
    if accum.get("kind", None) == "vrf":
        return parse_rtalist(accum, data, sel)
    return accum


_newlink_sel: RtaDesc = {
    IFLA_IFNAME: (to_str, "name"),
    IFLA_LINK: (to_int, "peer"),
    IFLA_MASTER: (to_int, "master"),
    IFLA_LINKINFO: (
        parse_rtalist,
        {
            IFLA_INFO_KIND: (to_str, "kind"),
            IFLA_INFO_DATA: (
                parse_rtalist_if_vrf,
                {
                    IFLA_VRF_TABLE: (to_int, "krt"),
                },
            ),
        },
    ),
}


def newlink_parser(message: bytes) -> Dict[str, Union[str, int]]:
    # pylint: disable=unused-variable
    family, if_type, index, flags, change = unpack("=BxHiII", message[:16])
    return parse_rtalist(
        {
            "ifindex": index,
            "is_up": bool(flags & IFF_UP),
        },
        message[16:],
        _newlink_sel,
    )


def nll_get_links(
    socket: Optional[socket] = None,
) -> Iterable[Dict[str, Union[str, int]]]:
    return nll_get_dump(
        RTM_GETLINK,
        RTM_NEWLINK,
        pack("Bxxx", AF_UNSPEC),
        newlink_parser,
        sk=socket,
    )


############################################################


def parse_nhlist(
    accum: Dict[str, Union[int, str, List[Dict[str, Union[int, str]]]]],
    data: bytes,
    key: str,
) -> Dict[str, Union[int, str, List[Dict[str, Union[int, str]]]]]:
    nhops = []
    while len(data) >= 8:
        # pylint: disable=unused-variable
        rtnh_len, rtnh_flags, rtnh_hops, rtnh_ifindex = unpack(
            "=HBBI", data[:8]
        )
        nhops.append(
            parse_rtalist(
                {
                    # "rtnh_flags": rtnh_flags,
                    # "rtnh_hops": rtnh_hops,
                    "ifindex": rtnh_ifindex,
                },
                data[8:rtnh_len],
                {RTA_GATEWAY: (to_ipaddr, "gateway")},
            )
        )
        data = data[rtnh_len:]
    if data:
        raise NllError(f"Remaining nexhop data: {data.hex()}")
    accum[key] = nhops
    return accum


_newroute_sel: RtaDesc = {
    RTA_DST: (to_ipaddr, "dst"),
    RTA_PRIORITY: (to_int, "metric"),
    RTA_TABLE: (to_int, "table"),
    RTA_OIF: (to_int, "ifindex"),
    RTA_GATEWAY: (to_ipaddr, "gateway"),
    RTA_MULTIPATH: (parse_nhlist, "multipath"),
}


def newroute_parser(
    message: bytes,
    table: int = 0,
    protocol: int = 0,
    scope: int = 0,
    type: int = 0,  # pylint: disable=redefined-builtin
) -> List[Dict[str, Union[str, int]]]:
    # pylint: disable=unused-variable
    (
        rtm_family,
        dst_len,
        src_len,
        rtm_tos,
        rtm_table,
        rtm_protocol,
        rtm_scope,
        rtm_type,
        rtm_flags,
    ) = unpack("=BBBBBBBBI", message[:12])
    if (
        # pylint: disable=too-many-boolean-expressions
        (table and rtm_table != table)
        or (protocol and rtm_protocol != protocol)
        or (scope and rtm_scope != scope)
        or (type and rtm_type != type)
    ):
        return []
    rtalist = parse_rtalist(
        {
            "family": rtm_family,
            "dst_prefixlen": dst_len,
            # "src_len": src_len,
            # "tos": rtm_tos,
            "table": rtm_table,
            # "protocol": rtm_protocol,
            # "scope": rtm_scope,
            "type": rtm_type,
            # "flags": rtm_flags,
        },
        message[12:],
        _newroute_sel,
    )
    multipath = rtalist.pop("multipath", None)
    if multipath is not None:
        return [{**rtalist, **nhop} for nhop in multipath]
    return [rtalist]


def nll_get_routes(
    socket: Optional[socket] = None,
    family: int = AF_UNSPEC,
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    return [
        el
        for subl in nll_get_dump(
            RTM_GETROUTE,
            RTM_NEWROUTE,
            pack("=BxxxxxxxI", family, 0),
            newroute_parser,
            sk=socket,
            **kwargs,
        )
        for el in subl
    ]
