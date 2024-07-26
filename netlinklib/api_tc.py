""" Netlink dump implementation replacement for pyroute2 """

from functools import partial
from socket import AF_UNSPEC, socket
from typing import (
    Any,
    Dict,
    Iterable,
    Optional,
    Union,
)
from .classes import tcmsg

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_tc import newtfilter_parser

__all__ = (
    "nll_filter_add",
    "nll_filter_change",
    "nll_filter_replace",
    "nll_filter_del",
    "nll_get_filters",
)


def nll_get_filters(
    ifindex: int,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        RTM_GETTFILTER,
        RTM_NEWTFILTER,
        tcmsg(
            tcm_family=AF_UNSPEC, tcm_ifindex=ifindex
        ).bytes,  # tcm_info = TC_H_MAKE(prio<<16, protocol);
        (),  # TCA_CHAIN, chain_index; TCA_KIND, k, strlen(k)+1
        newtfilter_parser,
        sk=socket,
        **kwargs,
    )


def _nll_filter(
    msg_type: int,
    nlm_flags: int,
    ifindex: int,
    kind: str,
    handle: Optional[int] = 0,  # Kernel needs either handle or clid
    parent: Optional[int] = 0,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[tcmsg]:
    """Manipulate filter of one interface"""
    msg = nll_transact(
        RTM_GETTFILTER,
        RTM_NEWTFILTER if msg_type == RTM_GETTFILTER else msg_type,
        tcmsg(
            tcm_family=AF_UNSPEC,
            tcm_ifindex=ifindex,
            tcm_handle=handle,
            tcm_parent=parent,
        ).bytes,
        tuple(
            (opt, fmt(val))  # type: ignore [no-untyped-call]
            for opt, fmt, val in (
                (TCA_KIND, lambda x: x.encode("ascii"), kind),
                # (TCA_OPTIONS, nest((TCA_HTB_INIT, tc_htb_glob),
                #                     (TCA_HTB_DIRECT_QLEN, int),
                #                     (TCA_HTB_OFFLOAD, bool),))
                # (TCA_RATE, tc_estimator),
                # (TCA_INGRESS_BLOCK, u32 ingress block),
                # (TCA_EGRESS_BLOCK, u32 egress block),
            )
            if val is not None
        ),
        nlm_flags=nlm_flags,
        sk=socket,
    )
    if msg is None:
        return None
    return tcmsg(msg) if msg else None


nll_filter_add = partial(
    _nll_filter, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL
)
nll_filter_change = partial(_nll_filter, RTM_NEWTFILTER, 0)
nll_filter_replace = partial(_nll_filter, RTM_NEWTFILTER, NLM_F_CREATE)
nll_filter_del = partial(_nll_filter, RTM_DELTFILTER, 0)
