""" Netlink dump implementation replacement for pyroute2 """

from functools import partial
from socket import AF_UNSPEC, socket
from typing import (
    Any,
    Callable,
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
from .parser_tc import newtfilter_parser, newqdisc_parser, newtclass_parser

__all__ = (
    "nll_get_filters",
    "nll_get_qdiscs",
    "nll_get_tclasses",
    "nll_filter_get",
    "nll_filter_add",
    "nll_filter_change",
    "nll_filter_replace",
    "nll_filter_del",
)


def _nll_tc_dump(
    msg_type: int,
    msg_resp: int,
    parser: Callable[[bytes], Dict[str, Union[str, int]]],
    ifindex: int,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        msg_type,
        msg_resp,
        tcmsg(
            tcm_family=AF_UNSPEC, tcm_ifindex=ifindex
        ).bytes,  # tcm_info = TC_H_MAKE(prio<<16, protocol);
        (),  # TCA_CHAIN, chain_index; TCA_KIND, k, strlen(k)+1
        parser,
        sk=socket,
        **kwargs,
    )


# only filter object has the GET operation (and probably not very useful).
def nll_filter_get(
    ifindex: int,
    kind: str,
    handle: int,
    parent: int,
    protocol: int,
    priority: int,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Dict[str, Union[str, int]]:
    """Get one filter entry"""
    msg = nll_transact(
        RTM_GETTFILTER,
        RTM_NEWTFILTER,
        tcmsg(
            tcm_family=AF_UNSPEC,
            tcm_ifindex=ifindex,
            tcm_handle=handle,
            tcm_parent=parent,
            tcm_info=(priority << 16) | protocol,
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
        nlm_flags=NLM_F_ECHO,  # Why? But `iproute2` sets it.
        sk=socket,
    )
    if msg is None:
        raise NllError(f"Empty response for RTM_GETTFILTER")
    return newtfilter_parser(msg)


def _nll_tc_op(
    msg_type: int,
    nlm_flags: int,
    ifindex: int,
    kind: str,
    handle: Optional[int] = 0,
    parent: Optional[int] = 0,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[tcmsg]:
    """Manipulate a TC object"""
    msg = nll_transact(
        msg_type,
        msg_type,
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
    if msg is not None:
        raise NllError(f"Unexpected response {tcmsg(msg)} for op {msg_type}")
    return None


# Dumps
nll_get_qdiscs = partial(
    _nll_tc_dump, RTM_GETQDISC, RTM_NEWQDISC, newqdisc_parser, 0
)
nll_get_filters = partial(
    _nll_tc_dump, RTM_GETTFILTER, RTM_NEWTFILTER, newtfilter_parser
)
nll_get_tclasses = partial(
    _nll_tc_dump, RTM_GETTCLASS, RTM_NEWTCLASS, newtclass_parser
)

# Individual object ops
nll_filter_add = partial(_nll_tc_op, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL)
nll_filter_change = partial(_nll_tc_op, RTM_NEWTFILTER, 0)
nll_filter_replace = partial(_nll_tc_op, RTM_NEWTFILTER, NLM_F_CREATE)
nll_filter_del = partial(_nll_tc_op, RTM_DELTFILTER, 0)
