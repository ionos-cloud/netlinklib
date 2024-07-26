""" Netlink dump implementation replacement for pyroute2 """

from functools import partial
from typing import Dict, Literal, Optional, Union
from .classes import tc_estimator, tc_htb_glob, tc_htb_opt, tc_ratespec, tcmsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newqdisc_parser", "newtclass_parser", "newtfilter_parser")


def parse_htb_glob(
    accum: Dict[str, Union[int, str]], data: bytes, _: Literal[None]
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_glob, used for tc qdisc"""
    hglob = tc_htb_glob(data)
    accum.update(
        {
            "version": hglob.version,
            "rate2quantum": hglob.rate2quantum,
            "defcls": hglob.defcls,
            "debug": hglob.debug,
            "direct_pkts": hglob.direct_pkts,
        }
    )
    return accum


def parse_htb_opt(
    accum: Dict[str, Union[int, str]], data: bytes, _: Literal[None]
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_opt, used for tc class"""
    htbopt = tc_htb_opt(data)
    accum.update(
        {
            "rate": tc_ratespec(htbopt.rate).rate,
            "ceil": tc_ratespec(htbopt.ceil).rate,
        }
    )
    return accum


_opt_qisc_sel: Dict[str, RtaDesc] = {
    "htb": {TCA_HTB_INIT: (parse_htb_glob, None)},
    "noqueue": {},
    "bfifo": {},  # TODO add support for tc_prio_qopt that has an array
    "pfifo": {},
    "pfifo_head_drop": {},
    "pfifo_fast": {},
}

_opt_class_sel: Dict[str, RtaDesc] = {
    "htb": {
        TCA_HTB_PARMS: (parse_htb_opt, None),
        TCA_HTB_RATE64: (to_int, "rate64"),
        TCA_HTB_CEIL64: (to_int, "ceil64"),
    }
}

_opt_filter_sel: Dict[str, RtaDesc] = {
    "flow": {
        TCA_FLOW_KEYS: (to_int, "keymask"),
        TCA_FLOW_MODE: (to_int, "flow_mode"),
        TCA_FLOW_BASECLASS: (to_int, "baseclass"),
    }
}


def parse_options_for_kind(
    accum: Dict[str, Union[int, str]], data: bytes, seld: Dict[str, RtaDesc]
) -> Dict[str, Union[int, str]]:
    """Parse TC_OPTIONS in a way suitable for the operation and kind"""
    kind = accum.get("kind", "<kind attribute not present>")
    sel: Optional[RtaDesc] = seld.get(str(kind), None)
    if sel is None:
        raise NotImplementedError(f"No parser selector for {kind} found")
    return parse_rtalist(accum, data, sel)


def _new_tc_parser(
    selector: RtaDesc, message: bytes
) -> Dict[str, Union[str, int]]:
    """Parser for all TC new* messages, to use with different selectors"""
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
        {
            TCA_KIND: (to_str, "kind"),
            TCA_OPTIONS: (parse_options_for_kind, selector),
            # TCA_STATS, TCA_STATS2, TCA_STATS_QUEUE
        },
    )


newqdisc_parser = partial(_new_tc_parser, _opt_qisc_sel)
newtclass_parser = partial(_new_tc_parser, _opt_class_sel)
newtfilter_parser = partial(_new_tc_parser, _opt_filter_sel)
