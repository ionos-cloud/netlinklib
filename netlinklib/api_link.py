""" Netlink dump implementation replacement for pyroute2 """

from errno import ENODEV
from socket import (
    socket,
)
from typing import (
    Dict,
    Iterable,
    Optional,
    Union,
)
from .classes import (
    ifinfomsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *
from .parser_link import newlink_parser

__all__ = "nll_get_links", "nll_link_lookup"


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
