""" Netlink dump implementation replacement for pyroute2 """

# False positive from pylint?
# pylint: disable=ungrouped-imports, wrong-import-order
from functools import partial
from ipaddress import ip_address
from socket import (
    AF_INET,
    AF_UNSPEC,
    socket,
)
from struct import pack
from typing import (
    Any,
    Dict,
    Iterable,
    Optional,
    Sequence,
    Union,
)
from .classes import (
    rtnexthop,
    rtmsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_route import newroute_parser

__all__ = "nll_get_routes", "nll_route_add", "nll_route_del"


def _nll_route(  # pylint: disable=too-many-arguments, too-many-locals
    msg_type: int,
    # rtmsg args
    family: int = AF_INET,
    dst_prefixlen: int = 0,
    src_prefixlen: int = 0,
    tos: int = 0,
    table: int = 254,  # RT_TABLE_MAIN
    protocol: int = RTPROT_BOOT,
    scope: int = RT_SCOPE_LINK,
    type: int = RTN_UNICAST,  # pylint: disable=redefined-builtin
    # rta args
    dst: Optional[str] = None,
    ifindex: Optional[int] = None,
    metric: Optional[int] = None,
    gateway: Optional[str] = None,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    multipath: Optional[Sequence[Dict[str, Union[int, str]]]] = None,
) -> None:
    def pack_multipath(
        # flags: int = 0,
        # hops: int = 0,
        ifindex: int = 0,
        gateway: Optional[str] = None,
    ) -> bytes:
        gwattr = (
            pack_attr(RTA_GATEWAY, ip_address(gateway).packed)
            if gateway
            else b""
        )
        size = 2 + 1 + 1 + 4 + len(gwattr)
        return (
            rtnexthop(
                rtnh_len=size,
                # rtnh_flags=flags,
                # rtnh_hops=hops,
                rtnh_ifindex=ifindex,
            ).bytes
            + gwattr
        )

    legacy_nll_transact(
        msg_type,
        msg_type,
        rtmsg(
            rtm_family=family,
            rtm_dst_len=dst_prefixlen,
            rtm_src_len=src_prefixlen,
            rtm_tos=tos,
            # rtm_table=table,  # use full length rtattr instead
            rtm_protocol=protocol,
            rtm_scope=scope,
            rtm_type=type,
        ).bytes,
        tuple(
            (opt, fmt(optval))  # type: ignore [no-untyped-call]
            for opt, fmt, optval in (
                (RTA_TABLE, lambda x: pack("=i", x), table),
                (RTA_DST, lambda ip: ip_address(ip).packed, dst),
                (RTA_OIF, lambda x: pack("=i", x), ifindex),
                (RTA_PRIORITY, lambda x: pack("=i", x), metric),
                (RTA_GATEWAY, lambda ip: ip_address(ip).packed, gateway),
                (
                    RTA_MULTIPATH,
                    lambda x: b"".join(pack_multipath(**path) for path in x),
                    multipath,
                ),
            )
            if optval is not None
        ),
        sk=socket,
        nlm_flags=NLM_F_CREATE,
    )


nll_route_add = partial(_nll_route, RTM_NEWROUTE)
nll_route_del = partial(_nll_route, RTM_DELROUTE)


def nll_get_routes(  # pylint: disable=too-many-arguments
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    family: int = AF_UNSPEC,
    flags: Optional[int] = None,
    protocol: Optional[int] = None,
    type: Optional[int] = None,  # pylint: disable=redefined-builtin
    table: Optional[int] = None,
    oif: Optional[int] = None,
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all routes"""
    # net/ipv4/fib_frontend.c:910
    rtm_kw = {
        k: v
        for k, v in (
            ("rtm_family", family),
            ("rtm_flags", flags),
            ("rtm_protocol", protocol),
            ("rtm_type", type),
        )
        if v is not None
    }
    # if table is not None and table <= 255:
    #     rtm_kw["rtm_table"] = table
    rtm_nla = tuple(
        (k, pack("=i", v))
        for k, v in ((RTA_TABLE, table), (RTA_OIF, oif))
        if v is not None
    )
    # print("rtm_kw", rtm_kw, "rtm_nla", rtm_nla)
    return [
        el
        for subl in legacy_nll_get_dump(
            RTM_GETROUTE,
            RTM_NEWROUTE,
            rtmsg(**rtm_kw).bytes,  # type: ignore
            rtm_nla,
            newroute_parser,
            sk=socket,
            **kwargs,
        )
        for el in subl
    ]
