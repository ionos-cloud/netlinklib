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
from .parser_tc import newqdisc_parser

__all__ = (
    "nll_qdisc_add",
    "nll_qdisc_change",
    "nll_qdisc_replace",
    "nll_qdisc_del",
    "nll_get_qdiscs",
)


def nll_get_qdiscs(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        RTM_GETQDISC,
        RTM_NEWQDISC,
        tcmsg(tcm_family=AF_UNSPEC).bytes,
        (),
        newqdisc_parser,
        sk=socket,
        **kwargs,
    )


def _nll_qdisc(
    msg_type: int,
    nlm_flags: int,
    ifindex: int,
    kind: str,
    handle: Optional[int] = 0,  # Kernel needs either handle or clid
    parent: Optional[int] = 0,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[tcmsg]:
    """Manipulate qdisc of one interface"""
    msg = nll_transact(
        RTM_GETQDISC,
        RTM_NEWQDISC if msg_type == RTM_GETQDISC else msg_type,
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


nll_qdisc_add = partial(_nll_qdisc, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL)
nll_qdisc_change = partial(_nll_qdisc, RTM_NEWQDISC, 0)
nll_qdisc_replace = partial(_nll_qdisc, RTM_NEWQDISC, NLM_F_CREATE)
nll_qdisc_del = partial(_nll_qdisc, RTM_DELQDISC, 0)
