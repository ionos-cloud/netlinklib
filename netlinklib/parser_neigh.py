""" Netlink dump implementation replacement for pyroute2 """

from typing import Dict, Union
from .classes import ndmsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newneigh_parser",)


_newneigh_sel: RtaDesc = {
    NDA_DST: (to_ipaddr, "dst"),
    NDA_LLADDR: (to_mac, "lladdr"),
}


def newneigh_parser(message: bytes) -> Dict[str, Union[str, int]]:
    """Parser for NEWNEIGH messages"""
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
