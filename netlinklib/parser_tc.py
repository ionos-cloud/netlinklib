""" Netlink dump implementation replacement for pyroute2 """

from functools import partial
from typing import Callable, Dict, List, Literal, Optional, Union
from .classes import (  # type: ignore [attr-defined]
    tc_estimator,
    tc_htb_glob,
    tc_fifo_qopt,
    tc_prio_qopt,
    tc_multiq_qopt,
    tc_htb_opt,
    tc_ratespec,
    tcmsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newqdisc_parser", "newtclass_parser", "newtfilter_parser")


def parse_htb_glob(
    accum: Dict[str, Union[int, str]], data: bytes, _: Literal[None]
) -> Dict[str, Union[int, str]]:
    """Parse tc_htb_glob, used for htb tc qdisc"""
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


QoptParser = Callable[
    [Dict[str, Union[int, str, List[int]]], bytes],
    Dict[str, Union[int, str, List[int]]],
]


def parse_fifo_qopt(
    accum: Dict[str, Union[int, str, List[int]]], data: bytes
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse tc_fifo_qopt, used for fifo tc qdisc"""
    fifo_qopt = tc_fifo_qopt(data)
    accum.update(
        {
            "limit": fifo_qopt.limit,
        }
    )
    return accum


def parse_prio_qopt(
    accum: Dict[str, Union[int, str, List[int]]], data: bytes
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse tc_fifo_qopt, used for fifo tc qdisc"""
    prio_qopt = tc_prio_qopt(data)
    accum.update(
        {
            "bands": prio_qopt.bands,
            "priomap": prio_qopt.priomap,
        }
    )
    return accum


def parse_multiq_qopt(
    accum: Dict[str, Union[int, str, List[int]]], data: bytes
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse tc_fifo_qopt, used for fifo tc qdisc"""
    multiq_qopt = tc_multiq_qopt(data)
    accum.update(
        {
            "bands": multiq_qopt.bands,
            "max_bands": multiq_qopt.max_bands,
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


# For some QDISCs, TCA_OPTIONS is a nested rtalist. For others, it's a struct.
_opt_qisc_sel: Dict[str, Union[RtaDesc, QoptParser]] = {
    "htb": {TCA_HTB_INIT: (parse_htb_glob, None)},
    "mq": parse_multiq_qopt,
    "noqueue": {},
    "bfifo": parse_fifo_qopt,
    "pfifo": parse_fifo_qopt,
    "pfifo_head_drop": parse_fifo_qopt,
    "pfifo_fast": parse_prio_qopt,
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
    accum: Dict[str, Union[int, str, List[int]]],
    data: bytes,
    seld: Dict[str, Union[RtaDesc, QoptParser]],
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse TC_OPTIONS in a way suitable for the operation and kind"""
    kind = accum.get("kind", "<kind attribute not present>")
    sel: Optional[Union[RtaDesc, QoptParser]] = seld.get(str(kind), None)
    if sel is None:
        raise NotImplementedError(f"No parser selector for {kind} found")
    if callable(sel):
        return sel(accum, data)
    return parse_rtalist(accum, data, sel)


def _new_tc_parser(
    selector: RtaDesc, message: bytes
) -> Dict[str, Union[str, int, List[int]]]:
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
