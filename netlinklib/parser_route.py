""" Netlink dump implementation replacement for pyroute2 """

from typing import (
    cast,
    Dict,
    List,
    Optional,
    Set,
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

__all__ = ("newroute_parser",)


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


def newroute_parser(  # pylint: disable=too-many-locals, too-many-arguments
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
    m_rtalist: Dict[str, Union[str, int, List[Dict[str, Union[str, int]]]]] = (
        parse_rtalist(
            {
                "family": rtm.rtm_family,
                "dst_prefixlen": rtm.rtm_dst_len,
                "table": rtm.rtm_table,
                "type": rtm.rtm_type,
                "protocol": rtm.rtm_protocol,
                "scope": rtm.rtm_scope,
            },
            rtm.remainder,
            _newroute_sel,
        )
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
