""" Netlink dump implementation replacement for pyroute2 """

from typing import Dict, Union
from .classes import tc_htb_glob, tcmsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newqdisc_parser",)


def parse_htb_glob(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_glob"""
    hglob = tc_htb_glob(data)
    accum.update({key: hglob.defcls})
    return accum


def parse_rtalist_if_htb(
    accum: Dict[str, Union[int, str]], data: bytes, sel: RtaDesc
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_glob only if kind == htb has been already put into accum"""
    if accum.get("kind", None) == "htb":
        return parse_rtalist(accum, data, sel)
    return accum


_newqisc_sel: RtaDesc = {
    TCA_KIND: (to_str, "kind"),
    TCA_OPTIONS: (
        parse_rtalist_if_htb,
        {TCA_HTB_INIT: (parse_htb_glob, "defcls")},
    ),
}


def newqdisc_parser(message: bytes) -> Dict[str, Union[str, int]]:
    """Parser for NEWNEIGH messages"""
    tcm = tcmsg(message)
    return parse_rtalist(
        {
            "ifindex": tcm.tcm_ifindex,
            "family": tcm.tcm_family,
            "handle": tcm.tcm_handle,
            "parent": tcm.tcm_parent,
            "info": tcm.tcm_info,
        },
        tcm.remainder,
        _newqisc_sel,
    )
