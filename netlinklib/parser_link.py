""" Netlink dump implementation replacement for pyroute2 """

from typing import Callable, Dict, Union
from .classes import ifinfomsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newlink_parser",)

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
