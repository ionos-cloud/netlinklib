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
from .parser_tclass import newtclass_parser

__all__ = (
    "nll_tclass_add",
    "nll_tclass_change",
    "nll_tclass_replace",
    "nll_tclass_del",
    "nll_get_tclasses",
)


def nll_get_tclasses(
    ifindex: int,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all tc classes of a device"""
    return nll_get_dump(
        RTM_GETTCLASS,
        RTM_NEWTCLASS,
        tcmsg(tcm_family=AF_UNSPEC, tcm_ifindex=ifindex).bytes,
        (),
        newtclass_parser,
        sk=socket,
    )


def _nll_tclass(
    msg_type: int,
    nlm_flags: int,
    ifindex: int,
    kind: str,
    handle: Optional[int] = 0,  # Kernel needs either handle or parent
    parent: Optional[int] = 0,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[tcmsg]:
    """Find tclass of one interface"""
    msg = nll_transact(
        RTM_GETTCLASS,
        RTM_NEWTCLASS if msg_type == RTM_GETTCLASS else msg_type,
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
                # (TCA_RATE, estimator),
            )
            if val is not None
        ),
        nlm_flags=nlm_flags,
        sk=socket,
    )
    return tcmsg(msg) if msg else None


nll_tclass_add = partial(_nll_tclass, RTM_NEWTCLASS, NLM_F_EXCL | NLM_F_CREATE)
nll_tclass_change = partial(_nll_tclass, RTM_NEWTCLASS, 0)
nll_tclass_replace = partial(_nll_tclass, RTM_NEWTCLASS, NLM_F_CREATE)
nll_tclass_del = partial(_nll_tclass, RTM_DELTCLASS, 0)
