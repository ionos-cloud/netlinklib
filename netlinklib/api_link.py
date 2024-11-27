""" Netlink dump implementation replacement for pyroute2 """

from errno import ENODEV
from functools import partial, wraps
from ipaddress import ip_address
from socket import (
    socket,
)
from struct import pack
from typing import (
    Callable,
    Dict,
    Iterable,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from .classes import (
    ifinfomsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_link import *

__all__ = "nll_link_add", "nll_link_del", "nll_get_links", "nll_link_lookup"

IFF_UP = 1


DataT = TypeVar("DataT", bytes, int, str)


def maybe(
    func: Callable[[DataT], bytes]
) -> Callable[[Optional[DataT]], Optional[bytes]]:
    @wraps(func)
    def _func(data: Optional[DataT]) -> Optional[bytes]:
        if data is None:
            return None
        return func(data)

    return _func


def _str(data: str) -> bytes:
    return data.encode("ascii") + b"\0"


def _int(data: int) -> bytes:
    return pack("=i", data)


def _be32(data: int) -> bytes:
    return pack(">i", data)


def _ipaddr(data: str) -> bytes:
    return ip_address(data).packed


def _bytes(data: bytes) -> bytes:
    return data


def _nested(*attrs: Tuple[int, Optional[bytes]]) -> bytes:
    return b"".join(
        pack_attr(opt, optval) for opt, optval in attrs if optval is not None
    )


Rtype = TypeVar("Rtype")


def _nll_link(
    msg_type: int,
    ifindex: int = 0,
    up: bool = False,
    name: Optional[str] = None,
    kind: Optional[str] = None,
    peer: Optional[int] = None,
    master: Optional[int] = None,
    # erspan
    erspan_ver: Optional[int] = None,
    gre_link: Optional[int] = None,
    gre_ikey: Optional[int] = None,
    gre_okey: Optional[int] = None,
    gre_local: Optional[str] = None,
    gre_remote: Optional[str] = None,
    # vrf
    krt: Optional[int] = None,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    parser: Optional[Callable[[bytes], Rtype]] = None,
) -> Optional[Rtype]:
    """
    If optional "parser" is provided, additional NLM_F_ECHO flag
    is sent, requesting original request to be echoed back (including
    any additional kernel-created fields such as `ifindex`.
    NOTE: This flag is only respected starting with kernel 6.3.
    """
    if kind is None:
        link_info = None
    else:
        link_info = pack_attr(IFLA_INFO_KIND, _str(kind))
        erspan_attrs = _nested(
            (IFLA_GRE_LINK, maybe(_int)(gre_link)),
            (IFLA_GRE_IFLAGS, _int(GRE_SEQ | GRE_KEY)),
            (IFLA_GRE_OFLAGS, _int(GRE_SEQ | GRE_KEY)),
            (IFLA_GRE_IKEY, maybe(_be32)(gre_ikey)),
            (IFLA_GRE_OKEY, maybe(_be32)(gre_okey)),
            (IFLA_GRE_LOCAL, maybe(_ipaddr)(gre_local)),
            (IFLA_GRE_REMOTE, maybe(_ipaddr)(gre_remote)),
            (IFLA_GRE_ERSPAN_VER, maybe(_int)(erspan_ver)),
        )
        link_info_attrs = {
            "erspan": erspan_attrs,
            "ip6erspan": erspan_attrs,
            "vrf": _nested((IFLA_VRF_TABLE, maybe(_int)(krt))),
        }
        if kind in link_info_attrs:
            link_info += pack_attr(IFLA_INFO_DATA, link_info_attrs[kind])
    ret = legacy_nll_transact(
        msg_type,
        msg_type,
        ifinfomsg(ifi_index=ifindex, ifi_flags=IFF_UP if up else 0).bytes,
        tuple(
            (opt, optval)
            for opt, optval in (
                (IFLA_IFNAME, maybe(_str)(name)),
                (IFLA_LINK, maybe(_int)(peer)),
                (IFLA_MASTER, maybe(_int)(master)),
                (IFLA_LINKINFO, maybe(_bytes)(link_info)),
            )
            if optval is not None
        ),
        sk=socket,
        nlm_flags=NLM_F_CREATE | (NLM_F_ECHO if parser else 0),
    )
    if parser:
        return parser(ret)
    return None


nll_link_add = partial(_nll_link, RTM_NEWLINK, parser=ifindex_parser)
nll_link_del = partial(_nll_link, RTM_DELLINK)


def nll_get_links(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    nameonly: bool = False,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all interfaces"""
    return legacy_nll_get_dump(
        RTM_GETLINK,
        RTM_NEWLINK,
        ifinfomsg().bytes,
        (),
        newlink_parser(nameonly),
        sk=socket,
    )


def nll_link_lookup(
    ifname: str,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
) -> Optional[int]:
    """Find ifindex by name"""
    try:
        msg = legacy_nll_transact(
            RTM_GETLINK,
            RTM_NEWLINK,
            ifinfomsg().bytes,
            ((IFLA_IFNAME, ifname.encode("ascii") + b"\0"),),
            sk=socket,
        )
    except NllError as e:
        if e.args[0] == -ENODEV:
            return None
        raise
    return ifinfomsg(msg).ifi_index  # ignore rtattrs
