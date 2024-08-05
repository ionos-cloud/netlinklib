""" Netlink dump implementation replacement for pyroute2 """

from array import array
from collections import defaultdict
from functools import partial
from socket import AF_UNSPEC, socket
from struct import pack
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)
from .classes import (
    tcmsg,
    tc_htb_opt,
    tc_htb_glob,
    tc_fifo_qopt,
    tc_multiq_qopt,
    tc_ratespec,
    tc_prio_qopt,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_tc import newtfilter_parser, newqdisc_parser, newtclass_parser

__all__ = (
    "nll_get_filters",
    "nll_get_qdiscs",
    "nll_get_classes",
    "nll_qdisc_add",
    "nll_qdisc_change",
    "nll_qdisc_replace",
    "nll_qdisc_link",
    "nll_qdisc_del",
    "nll_class_add",
    "nll_class_change",
    "nll_class_replace",
    "nll_class_del",
    "nll_filter_get",
    "nll_filter_add",
    "nll_filter_change",
    "nll_filter_replace",
    "nll_filter_del",
)


MAX_U32 = 2**32 - 1
HZ = 100  # Should maybe use `os.sysconf(os.sysconf_names['SC_CLK_TCK'])`
TIME_UNITS_PER_SEC = 1000000
with open("/proc/net/psched") as ps:
    t2us, us2t, clock_res, _ = map(lambda s: int(s, 16), ps.read().split())
if clock_res == 1000000000:
    t2us = us2t
clock_factor = clock_res / TIME_UNITS_PER_SEC  # float, expect < 1
tick_in_usec = t2us / us2t * clock_factor

U32t = (
    "L"
    if array("L").itemsize == 4
    else "I" if array("I").itemsize == 4 else None
)
assert U32t is not None, "What integer type has bytesize 4 on this system?!"


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
) -> Dict[str, Union[str, int, List[int]]]:
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


# Functions to use in _extra_attrs dictionary:


def no_attrs(**kwargs: Any) -> Tuple[Tuple[int, bytes], ...]:
    return ()


def blank_struct(
    structcls: Type[NllMsg],
) -> Callable[..., Tuple[Tuple[int, bytes], ...]]:
    return lambda: ((TCA_OPTIONS, structcls().bytes),)


def htb_qdisc_attrs(
    defcls: int = 0, rate2quantum: int = 10
) -> Tuple[Tuple[int, bytes], ...]:
    return (
        (
            TCA_OPTIONS,
            pack_attr(
                TCA_HTB_INIT,
                tc_htb_glob(
                    rate2quantum=rate2quantum, version=3, defcls=defcls
                ).bytes,
            ),
        ),
    )


def fifo_qdisc_attrs(limit: int = 0) -> Tuple[Tuple[int, bytes], ...]:
    return ((TCA_OPTIONS, tc_fifo_qopt(limit=limit).bytes),)


def prio_qdisc_attrs(
    multiq: bool = False,
    bands: int = 3,
    priomap: List[int] = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
) -> Tuple[Tuple[int, bytes], ...]:
    assert (
        len(priomap) == TC_PRIO_MAX + 1
    ), f"priomap must have {TC_PRIO_MAX+1} elements"
    return (
        (
            TCA_OPTIONS,
            tc_prio_qopt(bands=bands, priomap=priomap).bytes,
            # Quoting from iproute2:
            # /* This is the deprecated multiqueue interface */
            # + (pack_attr(TCA_PRIO_MQ, b"") if multiq else b""),
        ),
    )


def _get_size_and_cell(burst: Union[int, Tuple[int, int]]) -> Tuple[int, int]:
    if isinstance(burst, int):
        return burst, -1
    bufs, cell = burst
    clog = -1
    for i in range(31):
        if 1 << i == cell:
            clog = i
    return bufs, clog


def _tc_adjust_size(sz: int, mpu: int, linklayer: int) -> int:
    # ignore ATM that uses different adjustment
    return sz if sz >= mpu else mpu


def _make_ratespec_tab(
    cell_log: int = -1,
    linklayer: int = TC_LINKLAYER_ETHERNET,
    overhead: int = 0,
    mtu: int = 0,
    mpu: int = 0,
    rate: int = 0,
) -> Tuple[tc_ratespec, array]:  # type: ignore [type-arg]  # for new mypy
    if not mtu:
        mtu = 2047
    if cell_log < 0:
        cell_log = 0
        while (mtu >> cell_log) > 255:
            cell_log += 1
    rtab = array(
        U32t,  # type: ignore [arg-type]
        (
            int(
                tick_in_usec
                * TIME_UNITS_PER_SEC
                * _tc_adjust_size((i + 1) << cell_log, mpu, linklayer)
                / rate
            )
            for i in range(256)
        ),
    )
    return (
        tc_ratespec(
            cell_log=cell_log,
            linklayer=linklayer & TC_LINKLAYER_MASK,
            overhead=overhead,
            cell_align=-1,
            mpu=mpu,
            rate=MAX_U32 if rate > MAX_U32 else rate,
        ),
        rtab,
    )


def htb_class_attrs(
    prio: int = 0,
    mtu: int = 1600,
    mpu: int = 0,
    overhead: int = 0,
    linklayer: int = TC_LINKLAYER_ETHERNET,
    quantum: int = 0,
    burst: Union[int, Tuple[int, int]] = 0,
    cburst: Union[int, Tuple[int, int]] = 0,
    ceil: int = 0,
    rate: int = 0,
) -> Tuple[Tuple[int, bytes], ...]:
    assert rate, "Must specify non-zero rate"
    if not ceil:
        ceil = rate
    buffer, cell_log = _get_size_and_cell(burst)
    cbuffer, ccell_log = _get_size_and_cell(cburst)
    if not buffer:
        buffer = rate // HZ + mtu
    if not cbuffer:
        cbuffer = ceil // HZ + mtu
    optrate, rtab = _make_ratespec_tab(
        cell_log=cell_log,
        linklayer=linklayer,
        overhead=overhead,
        mtu=mtu,
        mpu=mpu,
        rate=rate,
    )
    optceil, ctab = _make_ratespec_tab(
        cell_log=ccell_log,
        linklayer=linklayer,
        overhead=overhead,
        mtu=mtu,
        mpu=mpu,
        rate=ceil,
    )
    return (
        (
            TCA_OPTIONS,
            (
                pack_attr(
                    TCA_HTB_PARMS,
                    tc_htb_opt(
                        rate=optrate.bytes,
                        ceil=optceil.bytes,
                        buffer=int(
                            tick_in_usec * TIME_UNITS_PER_SEC * buffer / rate
                        ),
                        cbuffer=int(
                            tick_in_usec * TIME_UNITS_PER_SEC * cbuffer / ceil
                        ),
                    ).bytes,
                )
                + (
                    pack_attr(TCA_HTB_RATE64, pack("=L", rate))
                    if rate > MAX_U32
                    else b""
                )
                + (
                    pack_attr(TCA_HTB_CEIL64, pack("=L", ceil))
                    if ceil > MAX_U32
                    else b""
                )
                + pack_attr(TCA_HTB_RTAB, rtab.tobytes())
                + pack_attr(TCA_HTB_CTAB, ctab.tobytes())
            ),
        ),
    )


_extra_attrs: Dict[
    Tuple[int, str], Callable[..., Tuple[Tuple[int, bytes], ...]]
] = defaultdict(
    lambda: no_attrs,
    {
        (RTM_NEWQDISC, "htb"): htb_qdisc_attrs,
        (RTM_NEWQDISC, "multiq"): blank_struct(tc_multiq_qopt),
        (RTM_NEWQDISC, "bfifo"): fifo_qdisc_attrs,
        (RTM_NEWQDISC, "pfifo"): fifo_qdisc_attrs,
        (RTM_NEWQDISC, "pfifo_head_drop"): fifo_qdisc_attrs,
        (RTM_NEWQDISC, "prio"): prio_qdisc_attrs,
        (RTM_NEWTCLASS, "htb"): htb_class_attrs,
    },
)


def _nll_tc_op(
    msg_type: int,
    nlm_flags: int,
    ifindex: int,
    kind: str,
    handle: Optional[int] = 0,
    parent: Optional[int] = 0,
    # estimator: Optional[tc_estimator] = None
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Any,
) -> None:
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
        (
            (TCA_KIND, kind.encode("ascii")),
            *(_extra_attrs[(msg_type, kind)](**kwargs)),
        ),
        nlm_flags=nlm_flags,
        sk=socket,
    )
    if msg:
        raise NllError(f"Unexpected response {msg!r} for op {msg_type}")


# Dumps
nll_get_qdiscs = partial(
    _nll_tc_dump, RTM_GETQDISC, RTM_NEWQDISC, newqdisc_parser, 0
)
nll_get_filters = partial(
    _nll_tc_dump, RTM_GETTFILTER, RTM_NEWTFILTER, newtfilter_parser
)
nll_get_classes = partial(
    _nll_tc_dump, RTM_GETTCLASS, RTM_NEWTCLASS, newtclass_parser
)

# Individual object ops
nll_qdisc_add = partial(_nll_tc_op, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL)
nll_qdisc_change = partial(_nll_tc_op, RTM_NEWQDISC, 0)
nll_qdisc_replace = partial(
    _nll_tc_op, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE
)
nll_qdisc_link = partial(_nll_tc_op, RTM_NEWQDISC, NLM_F_REPLACE)
nll_qdisc_del = partial(_nll_tc_op, RTM_DELQDISC, 0)

nll_class_add = partial(_nll_tc_op, RTM_NEWTCLASS, NLM_F_CREATE | NLM_F_EXCL)
nll_class_change = partial(_nll_tc_op, RTM_NEWTCLASS, 0)
nll_class_replace = partial(_nll_tc_op, RTM_NEWTCLASS, NLM_F_CREATE)
nll_class_del = partial(_nll_tc_op, RTM_DELTCLASS, 0)

nll_filter_add = partial(_nll_tc_op, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL)
nll_filter_change = partial(_nll_tc_op, RTM_NEWTFILTER, 0)
nll_filter_replace = partial(_nll_tc_op, RTM_NEWTFILTER, NLM_F_CREATE)
nll_filter_del = partial(_nll_tc_op, RTM_DELTFILTER, 0)
