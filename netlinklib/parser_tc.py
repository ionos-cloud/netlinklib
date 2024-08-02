""" Netlink dump implementation replacement for pyroute2 """

from functools import partial
from typing import Callable, Dict, List, Literal, Optional, Tuple, Type, Union
from .classes import (
    tc_estimator,
    tc_htb_glob,
    tc_fifo_qopt,
    tc_prio_qopt,
    tc_mirred,
    tc_multiq_qopt,
    tc_htb_opt,
    tc_ratespec,
    tc_u32_key,
    tc_u32_sel,
    tcmsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

__all__ = ("newqdisc_parser", "newtclass_parser", "newtfilter_parser")


def parse_one_class(
    cls: Type[NllMsg],
    accum: Dict[str, Union[int, str, List[int]]],
    data: bytes,
    _: Literal[None],
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse just a class"""
    accum.update(cls(data).dict)
    return accum


QoptParser = Callable[
    [Dict[str, Union[int, str, List[int]]], bytes],
    Dict[str, Union[int, str, List[int]]],
]


def parse_prio_qopt(
    accum: Dict[str, Union[int, str, List[int]]], data: bytes
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse tc_fifo_qopt, used for fifo tc qdisc"""
    prio_qopt = tc_prio_qopt(data)
    accum.update(
        {
            "bands": prio_qopt.bands,
            "priomap": list(prio_qopt.priomap),
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


def parse_mirred_parms(
    accum: Dict[str, Union[int, str]], data: bytes, _: Literal[None]
) -> Dict[str, Union[int, str]]:
    accum.update(tc_mirred(data).dict)
    return accum


_opt_tca_sel: Dict[Tuple[int, str], RtaDesc] = {
    (TCA_U32_ACT, "mirred"): {
        TCA_MIRRED_PARMS: (parse_mirred_parms, None),
        TCA_MIRRED_TM: (to_true, "mirred_tm"),
    },
}


def parse_tca_options_for_kind(
    accum: Dict[str, Union[int, str, List[int]]],
    data: bytes,
    actkind: int,
) -> Dict[str, Union[int, str, List[int]]]:
    """Parse TCA_OPTIONS in a way suitable for the operation and kind"""
    kind = accum.get("kind", "<kind attribute not present>")
    sel: Optional[RtaDesc] = _opt_tca_sel.get((actkind, str(kind)), None)
    if sel is None:
        raise NotImplementedError(f"No parser selector for {kind} found")
    return parse_rtalist(accum, data, sel)


def parse_tca_attrs(data: bytes, actkind: int) -> Dict[str, Union[int, str]]:
    return parse_rtalist(
        {},
        data,
        {
            TCA_ACT_KIND: (to_str, "kind"),
            TCA_ACT_OPTIONS: (parse_tca_options_for_kind, actkind),
            # TCA_ACT_STATS: {TCA_STATS_BASIC, TCA_STATS_QUEUE, ...}
        },
    )


AccuT = Dict[str, Union[int, str, Dict[int, Dict[str, Union[int, str]]]]]


def parse_tca_actions(accum: AccuT, data: bytes, actkind: int) -> AccuT:
    """Parser for TCA_xxx_ACT tlv. Nested tlvs have prios for tags."""
    act_dict = {
        rta_type: parse_tca_attrs(rta_data, actkind)
        for rta_type, rta_data in iterate_rtalist(data)
    }
    accum["actions"] = act_dict
    return accum


def parse_u32_sel(
    accum: Dict[
        str, Union[int, str, bytes, List[Dict[str, Union[int, str, bytes]]]]
    ],
    data: bytes,
    _: Literal[None],
) -> Dict[
    str, Union[int, str, bytes, List[Dict[str, Union[int, str, bytes]]]]
]:
    sel = tc_u32_sel(data)
    # sel.remainder contains a list of tc_u32_key that has to be parsed
    # separately.
    if len(sel.remainder) < (sel.nkeys * tc_u32_key.SIZE):
        raise NllError(
            f"parse_u32_sel nkeys={sel.nkeys} but only {len(sel.remainder)}"
            f" bytes of data. Need {sel.nkeys} * {tc_u32_key.SIZE} bytes"
        )
    accum.update(
        {
            "flags": sel.flags,
            "offshift": sel.offshift,
            "nkeys": sel.nkeys,
            "offmask": sel.offmask,
            "off": sel.off,
            "offoff": sel.offoff,
            "hoff": sel.hoff,
            "hmask": sel.hmask,
            "keys": [
                tc_u32_key(
                    sel.remainder[
                        i * tc_u32_key.SIZE : (i + 1) * tc_u32_key.SIZE
                    ]
                ).dict
                for i in range(sel.nkeys)
            ],
        }
    )
    return accum


# For some QDISCs, TCA_OPTIONS is a nested rtalist. For others, it's a struct.
_opt_qisc_sel: Dict[str, Union[RtaDesc, QoptParser]] = {
    "htb": {TCA_HTB_INIT: (partial(parse_one_class, tc_htb_glob), None)},
    "mq": partial(parse_one_class, tc_multiq_qopt),
    "noqueue": {},
    "bfifo": partial(parse_one_class, tc_fifo_qopt),
    "pfifo": partial(parse_one_class, tc_fifo_qopt),
    "pfifo_head_drop": partial(parse_one_class, tc_fifo_qopt),
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
    },
    "u32": {
        TCA_U32_FLAGS: (to_int, "flags"),
        TCA_U32_DIVISOR: (to_int, "divisor"),
        TCA_U32_SEL: (parse_u32_sel, None),
        TCA_U32_HASH: (to_int, "hash"),
        TCA_U32_CLASSID: (to_int, "classid"),
        TCA_U32_FLAGS: (to_int, "flags"),
        TCA_U32_ACT: (parse_tca_actions, TCA_U32_ACT),
    },
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
            TCA_CHAIN: (to_int, "chain"),
            # TCA_STATS, TCA_STATS2, TCA_STATS_QUEUE
        },
    )


newqdisc_parser = partial(_new_tc_parser, _opt_qisc_sel)
newtclass_parser = partial(_new_tc_parser, _opt_class_sel)
newtfilter_parser = partial(_new_tc_parser, _opt_filter_sel)
