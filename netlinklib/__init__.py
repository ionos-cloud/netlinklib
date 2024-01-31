""" Netlink dump implementation replacement for pyroute2 """

from socket import AF_BRIDGE, AF_UNSPEC, socket
from typing import (
    Any,
    Callable,
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from .classes import (
    genlmsghdr,
    ifinfomsg,
    nlmsghdr,
    rtattr,
    rtnexthop,
    rtmsg,
    ndmsg,
)
from .core import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .datatypes import NllError, RtaDesc
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
        genlmsghdr(cmd=0, version=0, reserved=0).bytes,
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
    m_rtalist: Dict[
        str, Union[str, int, List[Dict[str, Union[str, int]]]]
    ] = parse_rtalist(
        {
            "family": rtm.rtm_family,
            "dst_prefixlen": rtm.rtm_dst_len,
            "table": rtm.rtm_table,
            "type": rtm.rtm_type,
        },
        message[12:],
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


##############################################################

_newneigh_sel: RtaDesc = {
    NDA_DST: (to_ipaddr, "dst"),
    NDA_LLADDR: (to_mac, "lladdr"),
}


def newneigh_parser(message: bytes) -> Dict[str, Union[str, int]]:
    ndm = ndmsg(message[:12])
    # TODO: except ndm.ndm_state & NUD_PERMANENT
    return parse_rtalist(
        {
            "ifindex": ndm.ndm_ifindex,
            "family": ndm.ndm_family,
            "state": ndm.ndm_state,
            "flags": ndm.ndm_flags,
            "type": ndm.ndm_type,
        },
        message[12:],
        _newneigh_sel,
    )


def nll_get_neigh(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        RTM_GETNEIGH,
        RTM_NEWNEIGH,
        ndmsg(
            ndm_family=0,
            ndm_pad1=0,
            ndm_pad2=0,
            ndm_ifindex=0,
            ndm_state=0,
            ndm_flags=0,
            ndm_type=0,
        ).bytes,
        newneigh_parser,
        sk=socket,
        **kwargs,
    )
