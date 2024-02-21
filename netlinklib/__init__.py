""" Netlink dump implementation replacement for pyroute2 """

from errno import ENODEV
from functools import partial, reduce
from ipaddress import ip_address
from socket import (
    AF_BRIDGE,
    AF_INET,
    AF_NETLINK,
    AF_UNSPEC,
    NETLINK_ROUTE,
    SOCK_NONBLOCK,
    SOCK_RAW,
    socket,
)
from struct import pack
from typing import (
    Any,
    Callable,
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)
from .classes import (
    ifinfomsg,
    nlmsghdr,
    rtattr,
    rtnexthop,
    rtmsg,
    ndmsg,
)
from .core import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .datatypes import NllDumpInterrupted, NllError, RtaDesc
from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import

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

_newlink_nameonly_sel: RtaDesc = {
    IFLA_IFNAME: (to_str, "name"),
}


def newlink_parser(
    nameonly: bool = False,
) -> Callable[[bytes], Dict[str, Union[str, int]]]:
    selector = _newlink_nameonly_sel if nameonly else _newlink_sel

    def _newlink_parser(message: bytes) -> Dict[str, Union[str, int]]:
        """Parse NEW_LINK netlink message"""
        ifi = ifinfomsg(message)
        return parse_rtalist(
            {
                "ifindex": ifi.ifi_index,
                "is_up": bool(ifi.ifi_flags & IFF_UP),
            },
            ifi.remainder,
            selector,
        )

    return _newlink_parser


def nll_get_links(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    nameonly: bool = False,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all interfaces"""
    return nll_get_dump(
        RTM_GETLINK,
        RTM_NEWLINK,
        ifinfomsg().bytes,
        newlink_parser(nameonly),
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
        nh = rtnexthop(data)
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
    table_set: Optional[Set[int]] = None,
) -> List[Dict[str, Union[str, int]]]:
    """Parse NEW_ROUTE message"""
    rtm = rtmsg(message)
    # do not run expensive parse_rtalist if we know that we don't want this
    if (
        # pylint: disable=too-many-boolean-expressions
        (table_set is not None and rtm.rtm_table not in table_set)
        or (table and rtm.rtm_table != table)
        or (protocol and rtm.rtm_protocol != protocol)
        or (scope and rtm.rtm_scope != scope)
        or (type and rtm.rtm_type != type)
    ):
        return []
    m_rtalist: Dict[
        str, Union[str, int, List[Dict[str, Union[str, int]]]]
    ] = parse_rtalist(
        {
            "family": rtm.rtm_family,
            "dst_prefixlen": rtm.rtm_dst_len,
            "table": rtm.rtm_table,
            "type": rtm.rtm_type,
        },
        rtm.remainder,
        _newroute_sel,
    )
    multipath = cast(
        List[Dict[str, Union[str, int]]], m_rtalist.pop("multipath", None)
    )
    # assert multipath is None or isinstance(multipath, list)
    # assert all(isinstance(x, (str, int)) for x in m_rtalist.values())
    rtalist = cast(Dict[str, Union[str, int]], m_rtalist)
    if multipath is None:
        return [rtalist]
    return [{**rtalist, **nhop} for nhop in multipath]


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
            rtmsg(rtm_family=family).bytes,
            newroute_parser,
            sk=socket,
            **kwargs,
        )
        for el in subl
    ]


##############################################################

_newneigh_sel: RtaDesc = {
    NDA_DST: (to_ipaddr, "dst"),
    NDA_LLADDR: (to_mac, "lladdr"),
}


def newneigh_parser(message: bytes) -> Dict[str, Union[str, int]]:
    ndm = ndmsg(message)
    return parse_rtalist(
        {
            "ifindex": ndm.ndm_ifindex,
            "state": ndm.ndm_state,
            "flags": ndm.ndm_flags,
            "type": ndm.ndm_type,
        },
        ndm.remainder,
        _newneigh_sel,
    )


def nll_get_neigh(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    family: int = AF_BRIDGE,
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        RTM_GETNEIGH,
        RTM_NEWNEIGH,
        ndmsg(ndm_family=family).bytes,
        newneigh_parser,
        sk=socket,
        **kwargs,
    )


##############################################################


def nll_link_lookup(
    ifname: str,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[int]:
    try:
        msg = nll_transact(
            RTM_GETLINK,
            RTM_NEWLINK,
            ifinfomsg().bytes,
            ((IFLA_IFNAME, ifname.encode("ascii") + b"\0"),),
            sk=socket,
        )
    except NllError as e:
        if e.args[0] == -ENODEV:
            return None
        raise
    return ifinfomsg(msg).ifi_index  # ignore rtattrs


##############################################################


def _nll_route(
    msg_type: int,
    # rtmsg args
    family: int = AF_INET,
    dst_prefixlen: int = 0,
    src_prefixlen: int = 0,
    tos: int = 0,
    table: int = 254,  # RT_TABLE_MAIN
    protocol: int = RTPROT_BOOT,
    scope: int = RT_SCOPE_LINK,
    type: int = RTN_UNICAST,
    # rta args
    dst: Optional[str] = None,
    ifindex: Optional[int] = None,
    metric: Optional[int] = None,
    gateway: Optional[str] = None,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> None:
    nll_transact(
        msg_type,
        msg_type,
        rtmsg(
            rtm_family=family,
            rtm_dst_len=dst_prefixlen,
            rtm_src_len=src_prefixlen,
            rtm_tos=tos,
            rtm_table=table,
            rtm_protocol=protocol,
            rtm_scope=scope,
            rtm_type=type,
        ).bytes,
        tuple(
            (opt, fmt(optval))
            for opt, fmt, optval in (
                (RTA_TABLE, lambda x: pack("i", x), table),
                (RTA_DST, lambda ip: ip_address(ip).packed, dst),
                (RTA_OIF, lambda x: pack("i", x), ifindex),
                (RTA_PRIORITY, lambda x: pack("i", x), metric),
                (RTA_GATEWAY, lambda ip: ip_address(ip).packed, gateway),
            )
            if optval is not None
        ),
        sk=socket,
        nlm_flags=NLM_F_CREATE,
    )


nll_route_add = partial(_nll_route, RTM_NEWROUTE)
nll_route_del = partial(_nll_route, RTM_DELROUTE)


##############################################################


_SUPPORTED_GROUPS = {
    # RTMGRP_IPV4_IFADDR,
    # RTMGRP_IPV6_IFADDR,
    RTMGRP_IPV4_ROUTE: (RTM_NEWROUTE, RTM_DELROUTE),
    RTMGRP_IPV6_ROUTE: (RTM_NEWROUTE, RTM_DELROUTE),
    RTMGRP_NEIGH: (RTM_NEWNEIGH, RTM_DELNEIGH),
    RTMGRP_LINK: (RTM_NEWLINK, RTM_DELLINK),
}


_SUPPORTED_EVENTS: Dict[int, Callable[[bytes], Any]] = {
    # TODO: Add new parsers
    # RTM_NEWADDR: newaddr_parser,
    # RTM_DELADDR: newaddr_parser,
    RTM_NEWLINK: newlink_parser(),
    RTM_DELLINK: newlink_parser(),
    RTM_NEWNEIGH: newneigh_parser,
    RTM_DELNEIGH: newneigh_parser,
    RTM_NEWROUTE: newroute_parser,
    RTM_DELROUTE: newroute_parser,
}


def nll_make_event_listener(*groups: int, block=False) -> socket:
    """
    Create socket bound to given groups, for use with `nll_get_events`.
    If no groups are given, subscribe to all supported groups.
    Sockets created with `block=False` will only produce output
    if a read is ready and should be used with select/poll.
    Sockets created with `block=True` will produce an endless
    blocking iterator which yields events as they become ready.
    """
    unsupported = set(groups) - set(_SUPPORTED_GROUPS)
    if unsupported:
        raise NllError(f"Unsupported group(s) requested: {unsupported}")
    sock = socket(
        AF_NETLINK, SOCK_RAW | (0 if block else SOCK_NONBLOCK), NETLINK_ROUTE
    )
    sock.bind(
        (
            0,
            reduce(
                lambda x, y: x | y, groups if groups else _SUPPORTED_GROUPS
            ),
        )
    )
    return sock


def nll_get_events(sk: socket) -> Iterable[Tuple[int, Any]]:
    """
    Socket should already be bound to correct multicast group addr.
    If `events` are given, only parse and return matching events.
    """
    return nll_handle_event(_SUPPORTED_EVENTS, sk)
