""" Netlink dump implementation replacement for pyroute2 """

from typing import Dict, Union
from .classes import tc_ratespec, tc_htb_opt, tcmsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newtclass_parser",)


def parse_htb_opt(
    accum: Dict[str, Union[int, str]], data: bytes, sel: RtaDesc
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_opt"""
    htbopt = tc_htb_opt(data)
    accum.update(
        {
            "rate": tc_ratespec(htbopt.rate).rate,
            "ceil": tc_ratespec(htbopt.ceil).rate,
        }
    )
    return accum


def parse_rtalist_if_htb(
    accum: Dict[str, Union[int, str]], data: bytes, sel: RtaDesc
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_opt only if kind == htb has been already put into accum"""
    if accum.get("kind", None) == "htb":
        accum = parse_rtalist(accum, data, sel)
        # Do we want the following magic?
        if "ceil64" in accum:
            accum["ceil"] = accum["ceil64"]
            del accum["ceil64"]
        if "rate64" in accum:
            accum["rate"] = accum["rate64"]
            del accum["rate64"]
    return accum


_newtclass_sel: RtaDesc = {
    TCA_KIND: (to_str, "kind"),
    TCA_OPTIONS: (
        parse_rtalist_if_htb,
        {
            TCA_HTB_PARMS: (parse_htb_opt, {}),
            TCA_HTB_RATE64: (to_int, "rate64"),
            TCA_HTB_CEIL64: (to_int, "ceil64"),
        },
    ),
}


def newtclass_parser(message: bytes) -> Dict[str, Union[str, int]]:
    """Parser for NEWTCLASS messages"""
    tcm = tcmsg(message)
    return parse_rtalist(
        {
            # "family": tcm.tcm_family,
            "handle": tcm.tcm_handle,
            "parent": tcm.tcm_parent,
            # "info": tcm.tcm_info,
        },
        tcm.remainder,
        _newtclass_sel,
    )
