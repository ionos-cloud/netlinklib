""" Netlink dump implementation replacement for pyroute2 """

from typing import Callable, Dict, Optional, Union, cast
from .classes import ifinfomsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newlink_parser", "ifindex_parser")

IFF_UP = 1


def parse_rtalist_by_kind(
    accum: Dict[str, Union[int, str]], data: bytes, descs: Dict[str, RtaDesc]
) -> Dict[str, Union[int, str]]:
    """Parse KRT only if kind == vrf has been already put into accum"""
    sel = descs.get(cast(str, accum.get("kind")))
    if sel is None:
        return accum
    return parse_rtalist(accum, data, sel)


_erspan_attrs = {
    IFLA_GRE_ERSPAN_VER: (to_int, "erspan_ver"),
    IFLA_GRE_IKEY: (to_int_be, "gre_ikey"),
    IFLA_GRE_OKEY: (to_int_be, "gre_okey"),
    IFLA_GRE_LOCAL: (to_ipaddr, "gre_local"),
    IFLA_GRE_REMOTE: (to_ipaddr, "gre_remote"),
    IFLA_GRE_LINK: (to_int, "gre_link"),
}
_newlink_sel: RtaDesc = {
    IFLA_IFNAME: (to_str, "name"),
    IFLA_LINK: (to_int, "peer"),
    IFLA_MASTER: (to_int, "master"),
    IFLA_LINKINFO: (
        parse_rtalist,
        {
            IFLA_INFO_KIND: (to_str, "kind"),
            IFLA_INFO_DATA: (
                parse_rtalist_by_kind,
                {
                    "vrf": {
                        IFLA_VRF_TABLE: (to_int, "krt"),
                    },
                    "erspan": _erspan_attrs,
                    "ip6erspan": _erspan_attrs,
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
    """Parser for NEWLINK message"""
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


def ifindex_parser(message: bytes) -> Optional[int]:
    if message:
        return ifinfomsg(message).ifi_index
    return None
