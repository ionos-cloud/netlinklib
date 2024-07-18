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
from .parser_qdisc import newqdisc_parser

__all__ = (
    "nll_qdisc_get",
    "nll_qdisc_add",
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
    ifindex: int,
    handle: Optional[int] = 0,  # Kernel needs either handle or clid
    clid: Optional[int] = 0,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[tcmsg]:
    """Find qdisc of one interface"""
    msg = nll_transact(
        RTM_GETQDISC,
        RTM_NEWQDISC if msg_type == RTM_GETQDISC else msg_type,
        tcmsg(
            tcm_family=AF_UNSPEC,
            tcm_ifindex=ifindex,
            tcm_handle=handle,
            tcm_parent=clid,
        ).bytes,
        (),
        sk=socket,
    )
    return tcmsg(msg) if msg else None


nll_qdisc_get = partial(_nll_qdisc, RTM_GETQDISC)
nll_qdisc_add = partial(_nll_qdisc, RTM_NEWQDISC)
nll_qdisc_del = partial(_nll_qdisc, RTM_DELQDISC)
