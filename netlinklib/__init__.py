""" Netlink dump implementation replacement for pyroute2 """

from os import getpid
from socket import AF_NETLINK, AF_UNSPEC, NETLINK_ROUTE, SOCK_RAW, socket
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
from .classes import genlmsghdr, ifinfomsg, nlmsghdr, rtattr, rtnexthop, rtmsg

__all__ = ("NllDumpInterrupted", "NllError", "nll_get_links", "nll_get_routes")


class NllError(BaseException):
    """Any exception originating from here"""


class NllDumpInterrupted(NllError):
    """ "dump interrupted" condition reported by the kernel"""


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
        mh = nlmsghdr(buf[:16])
        if datasize < mh.nlmsg_len:
            raise NllError(
                f"data size {datasize} less then msg_len {mh.nlmsg_len}:"
                f" {buf.hex()}"
            )
        if mh.nlmsg_type == NLMSG_DONE:
            return
        message = buf[16 : mh.nlmsg_len]
        buf = buf[mh.nlmsg_len :]
        yield (
            mh.nlmsg_type,
            mh.nlmsg_flags,
            mh.nlmsg_seq,
            mh.nlmsg_pid,
            message,
        )


Rtype = TypeVar("Rtype")


def _nll_get_dump(  # pylint: disable=too-many-locals
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
    nlhdr = nlmsghdr(
        nlmsg_len=size,
        nlmsg_type=typ,
        nlmsg_flags=flags,
        nlmsg_seq=seq,
        nlmsg_pid=pid,
    ).bytes
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
    """Accumulating function that saves a string"""
    accum[key] = data.rstrip(b"\0").decode("ascii")
    return accum


def to_int(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves an integer"""
    accum[key] = int.from_bytes(data, byteorder=byteorder)
    return accum


def to_ipaddr(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves IP address in the form of s string"""
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
    """Walk over a chunk with collection of RTAs and collect RTAs"""
    while data:
        if len(data) < 4:
            raise NllError(f"data len {len(data)} < 4: {data.hex()}")
        rta = rtattr(data[:4])
        if rta.rta_len < 4:
            raise NllError(f"rta_len {rta.rta_len} < 4: {data.hex()}")
        rta_data = data[4 : rta.rta_len]
        increment = (rta.rta_len + 4 - 1) & ~(4 - 1)
        if len(data) < increment:
            raise NllError(f"data len {len(data)} < {increment}: {data.hex()}")
        data = data[increment:]
        if rta.rta_type in sel:
            op, *args = sel[rta.rta_type]
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
    """Parse NEW_LINK netlink message"""
    ifi = ifinfomsg(message[:16])
    return parse_rtalist(
        {
            "ifindex": ifi.ifi_index,
            "is_up": bool(ifi.ifi_flags & IFF_UP),
        },
        message[16:],
        _newlink_sel,
    )


def nll_get_links(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all interfaces"""
    return nll_get_dump(
        RTM_GETLINK,
        RTM_NEWLINK,
        genlmsghdr(cmd=AF_UNSPEC, version=0, reserved=0).bytes,
        newlink_parser,
        sk=socket,
    )


############################################################


def parse_nhlist(
    accum: Dict[str, Union[int, str, List[Dict[str, Union[int, str]]]]],
    data: bytes,
    key: str,
) -> Dict[str, Union[int, str, List[Dict[str, Union[int, str]]]]]:
    """Parse a sequence of "nexthop" records in the "MULTIPATH" RTA"""
    nhops: List[Dict[str, Union[int, str]]] = []
    while len(data) >= 8:
        nh = rtnexthop(data[:8])
        nhops.append(
            parse_rtalist(
                {
                    # "rtnh_flags": rtnh_flags,
                    # "rtnh_hops": rtnh_hops,
                    "ifindex": nh.rtnh_ifindex,
                },
                data[8 : nh.rtnh_len],
                {RTA_GATEWAY: (to_ipaddr, "gateway")},
            )
        )
        data = data[nh.rtnh_len :]
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


def newroute_parser(  # pylint: disable=too-many-locals
    message: bytes,
    table: int = 0,
    protocol: int = 0,
    scope: int = 0,
    type: int = 0,  # pylint: disable=redefined-builtin
) -> List[Dict[str, Union[str, int]]]:
    """Parse NEW_ROUTE message"""
    rtm = rtmsg(message[:12])
    if (
        # pylint: disable=too-many-boolean-expressions
        (table and rtm.rtm_table != table)
        or (protocol and rtm.rtm_protocol != protocol)
        or (scope and rtm.rtm_scope != scope)
        or (type and rtm.rtm_type != type)
    ):
        return []
    rtalist: Dict[str, Union[str, int]] = parse_rtalist(
        {
            "family": rtm.rtm_family,
            "dst_prefixlen": rtm.rtm_dst_len,
            # "src_len": src_len,
            # "tos": rtm_tos,
            "table": rtm.rtm_table,
            # "protocol": rtm_protocol,
            # "scope": rtm_scope,
            "type": rtm.rtm_type,
            # "flags": rtm_flags,
        },
        message[12:],
        _newroute_sel,
    )
    # the real error:
    # netlinklib/__init__.py:323: error: Incompatible types in assignment
    # (expression has type "str | int | None", variable has type
    # "list[dict[str, str | int]] | None")  [assignment]
    # Leave it TODO later
    multipath: Optional[
        List[Dict[str, Union[str, int]]]
    ] = rtalist.pop(  # type:ignore
        "multipath", None
    )
    if multipath is not None:
        return [{**rtalist, **nhop} for nhop in multipath]
    return [rtalist]


def nll_get_routes(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    family: int = AF_UNSPEC,
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all routes"""
    return [
        el
        for subl in nll_get_dump(
            RTM_GETROUTE,
            RTM_NEWROUTE,
            rtmsg(
                rtm_family=family,
                rtm_dst_len=0,
                rtm_src_len=0,
                rtm_tos=0,
                rtm_table=0,
                rtm_protocol=0,
                rtm_scope=0,
                rtm_type=0,
                rtm_flags=0,
            ).bytes,
            newroute_parser,
            sk=socket,
            **kwargs,
        )
        for el in subl
    ]
