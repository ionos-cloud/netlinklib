""" Netlink dump implementation replacement for pyroute2 """

from errno import ENODEV
from functools import partial
from socket import (
    socket,
)
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)
from .classes import (
    ifinfomsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_link import newlink_parser

__all__ = (
    "nll_link_add",
    "nll_link_del",
    "nll_get_links",
    "nll_link_lookup",
    "alt_nll_get_links",
    "alt_nll_link_lookup",
)

IFF_UP = 1


class NestedByKind(NlaNested):
    def __init__(self, **nlas_by_kind: Sequence[Tuple[int, NlaType]]) -> None:
        self.nlas_by_kind = nlas_by_kind
        super().__init__()

    def encode(self, **kwargs: Any) -> bytes:
        # TODO: could be optimized
        super().__init__(
            *self.nlas_by_kind.get(cast(str, kwargs.get("kind", "")), ())
        )
        return super().encode()

    def parse(
        self,
        accum: Dict[str, Union[int, str]],
        data: bytes,
        **kwargs: Any,
    ) -> Dict[str, Union[int, str]]:
        # TODO: could be optimized
        super().__init__(
            *self.nlas_by_kind.get(cast(str, accum.get("kind")), ())
        )
        return super().parse(accum, data, **kwargs)


LINK_NLA = NlaHeader(
    ifinfomsg,
    (
        ("ifi_flags", "flags"),
        ("ifi_index", "ifindex"),
    ),
    (IFLA_IFNAME, NlaStr("ifname")),
    (IFLA_LINK, NlaInt("peer")),
    (IFLA_MASTER, NlaInt("master")),
    (
        IFLA_LINKINFO,
        NlaNested(
            (IFLA_INFO_KIND, NlaStr("kind")),
            (
                IFLA_INFO_DATA,
                NestedByKind(
                    vrf=((IFLA_VRF_TABLE, NlaInt("krt")),),
                    erspan=(
                        (IFLA_GRE_ERSPAN_VER, NlaInt("erspan_ver")),
                        (IFLA_GRE_IKEY, NlaBe32("gre_ikey")),
                        (IFLA_GRE_OKEY, NlaBe32("gre_okey")),
                        (IFLA_GRE_LOCAL, NlaIpaddr("gre_local")),
                        (IFLA_GRE_REMOTE, NlaIpaddr("gre_remote")),
                    ),
                ),
            ),
        ),
    ),
)


def _nll_link(  # pylint: disable=too-many-arguments
    msg_type: int,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Union[int, str],
) -> None:
    """Add/remove a link."""
    alt_nll_transact(
        msg_type,
        msg_type,
        LINK_NLA,
        sk=socket,
        nlm_flags=NLM_F_CREATE,
        **kwargs,
    )


nll_link_add = partial(_nll_link, RTM_NEWLINK)
nll_link_del = partial(_nll_link, RTM_DELLINK)


def nll_get_links(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    nameonly: bool = False,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all interfaces"""
    return nll_get_dump(
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
        msg = nll_transact(
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


def add_is_up(
    iter: Iterable[Dict[str, Union[str, int]]]
) -> Iterable[Dict[str, Union[str, int]]]:
    return (
        {"is_up": bool(cast(int, link["flags"]) & IFF_UP), **link}
        for link in iter
    )


@apply(add_is_up)
def alt_nll_get_links(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    nameonly: bool = False,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all interfaces"""
    return alt_nll_get_dump(
        RTM_GETLINK,
        RTM_NEWLINK,
        LINK_NLA,
        sk=socket,
        select={"name"} if nameonly else None,
    )


def alt_nll_link_lookup(
    ifname: str,
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    **kwargs: Union[int, str],
) -> Optional[int]:
    """Find ifindex by name"""
    try:
        return cast(
            int,
            alt_nll_transact(
                RTM_GETLINK,
                RTM_NEWLINK,
                LINK_NLA,
                sk=socket,
                ifname=ifname,
            ).get("ifindex"),
        )
    except NllError as e:
        if e.args[0] == -ENODEV:
            return None
        raise
