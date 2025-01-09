from collections import defaultdict
from functools import partial
from ipaddress import ip_address
from socket import socket
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from netlinklib import *


IFF_UP = 1

Accum = TypeVar("Accum")


def raise_exc(exc: Union[Exception, Type[Exception]]) -> NoReturn:
    raise exc


class LinkAccum:
    __slots__ = (
        "family",
        "index",
        "is_up",
        "name",
        "peer",
        "master",
        "kind",
        "krt",
        "erspan_ver",
        "gre_ikey",
        "gre_okey",
        "gre_local",
        "gre_remote",
        "gre_link",
    )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join(
                f"{k}={repr(getattr(self, k))}"
                for k in self.__slots__
                if hasattr(self, k)
            )
            + ")"
        )


def saveas(
    key: str, transform: Callable[[Any], Any] = lambda x: x
) -> Callable[[Accum, Any], Accum]:
    def _saveas(accum: Accum, val: Any) -> Accum:
        setattr(accum, key, transform(val))
        return accum

    return _saveas


def dummy_attrs() -> Tuple[NlaAttr, ...]:
    return (NlaStr(IFLA_INFO_KIND, "dummy"),)


def erspan_attrs(
    erspan_ver: Optional[int] = None,
    gre_link: Optional[int] = None,
    gre_ikey: Optional[int] = None,
    gre_okey: Optional[int] = None,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaInt32(IFLA_GRE_LINK, gre_link),
        NlaInt32(IFLA_GRE_IFLAGS, (GRE_SEQ | GRE_KEY)),
        NlaInt32(IFLA_GRE_OFLAGS, (GRE_SEQ | GRE_KEY)),
        NlaBe32(IFLA_GRE_IKEY, gre_ikey),
        NlaBe32(IFLA_GRE_OKEY, gre_okey),
        NlaInt32(IFLA_GRE_ERSPAN_VER, erspan_ver),
    )


def erspan4_attrs(
    gre_local: Optional[str] = None,
    gre_remote: Optional[str] = None,
    **kwargs: Any,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, "erspan"),
        NlaNest(
            IFLA_INFO_DATA,
            *erspan_attrs(**kwargs),
            NlaIp4(IFLA_GRE_LOCAL, gre_local),
            NlaIp4(IFLA_GRE_REMOTE, gre_remote),
        ),
    )


def erspan6_attrs(
    gre_local: Optional[str] = None,
    gre_remote: Optional[str] = None,
    **kwargs: Any,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, "ip6erspan"),
        NlaNest(
            IFLA_INFO_DATA,
            *erspan_attrs(**kwargs),
            NlaIp6(IFLA_GRE_LOCAL, gre_local),
            NlaIp6(IFLA_GRE_REMOTE, gre_remote),
        ),
    )


def vrf_attrs(krt: Optional[int] = None) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, "vrf"),
        NlaNest(IFLA_INFO_DATA, NlaInt32(IFLA_VRF_TABLE, krt)),
    )


def vxlan_attrs(
    vxlan_id: Optional[int] = None,
    vxlan_local: Optional[str] = None,
    vxlan_learning: Optional[bool] = None,
    vxlan_port: Optional[int] = None,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, "vxlan"),
        NlaNest(
            IFLA_INFO_DATA,
            NlaInt32(IFLA_VXLAN_ID, vxlan_id),
            NlaIp4(IFLA_VXLAN_LOCAL, vxlan_local),
            NlaInt32(IFLA_VXLAN_LEARNING, vxlan_learning),
            NlaInt32(IFLA_VXLAN_PORT, vxlan_port),
        ),
    )


def link_attrs(
    ifindex: int = 0,
    up: bool = False,
    name: Optional[str] = None,
    kind: Optional[str] = None,
    peer: Optional[int] = None,
    master: Optional[int] = None,
    **kwargs: Any,
) -> NlaStruct:
    return NlaStruct(
        ifinfomsg(ifi_index=ifindex, ifi_flags=IFF_UP if up else 0),
        NlaStr(IFLA_IFNAME, name),
        NlaInt32(IFLA_LINK, peer),
        NlaInt32(IFLA_MASTER, master),
        *(
            (
                NlaNest(
                    IFLA_LINKINFO,
                    *cast(
                        Dict[str, Callable[..., Tuple[NlaAttr, ...]]],
                        {
                            "dummy": dummy_attrs,
                            "erspan": erspan4_attrs,
                            "ip6erspan": erspan6_attrs,
                            "vrf": vrf_attrs,
                            "vxlan": vxlan_attrs,
                        },
                    )[kind](**kwargs),
                ),
            )
            if kind
            else ()
        ),
    )


def _link(
    msg_type: int,
    sk: Optional[socket] = None,
    parser: Optional[Callable[[bytes], Optional[Accum]]] = None,
    **kwargs: Any,
) -> Optional[Accum]:
    return (parser if parser is not None else lambda msg: None)(
        nll_transact(
            msg_type,
            msg_type,
            link_attrs(**kwargs).to_bytes(),
            sk=sk,
            flags=NLM_F_CREATE | (NLM_F_ECHO if parser else 0),
        )
    )


link_add = partial(
    _link,
    RTM_NEWLINK,
    parser=lambda msg: ifinfomsg(msg).ifi_index if msg else None,
)
link_del = partial(_link, RTM_DELLINK)


def get_links(
    nameonly: bool = False,
    sk: Optional[socket] = None,
) -> List[LinkAccum]:
    if nameonly:
        parser = NlaStruct(
            ifinfomsg(
                ifi_index=saveas("index"),
                ifi_flags=saveas(
                    "is_up",
                    transform=lambda v: bool(v & IFF_UP),
                ),
            ),
            NlaStr(IFLA_IFNAME, saveas("name")),
        )
    else:
        parser = NlaStruct(
            ifinfomsg(
                # ifi_index=1,
                ifi_index=saveas("index"),
                ifi_flags=(
                    saveas(
                        "is_up",
                        transform=lambda v: bool(v & IFF_UP),
                    ),
                ),
            ),
            NlaStr(IFLA_IFNAME, saveas("name")),
            NlaInt32(IFLA_LINK, saveas("peer")),
            NlaInt32(IFLA_MASTER, saveas("master")),
            NlaNest(
                IFLA_LINKINFO,
                NlaStr(IFLA_INFO_KIND, saveas("kind")),
                NlaUnion(
                    IFLA_INFO_DATA,
                    resolve=lambda accum: defaultdict(
                        lambda: raise_exc(StopParsing),
                        {
                            "vrf": NlaNest(
                                IFLA_INFO_DATA,
                                NlaInt32(IFLA_VRF_TABLE, saveas("krt")),
                            ),
                            "erspan": NlaNest(
                                IFLA_INFO_DATA,
                                *(
                                    erspan_attrs := (
                                        NlaInt32(
                                            IFLA_GRE_ERSPAN_VER,
                                            saveas("erspan_ver"),
                                        ),
                                        NlaBe32(
                                            IFLA_GRE_IKEY,
                                            saveas("gre_ikey"),
                                        ),
                                        NlaBe32(
                                            IFLA_GRE_OKEY,
                                            saveas("gre_okey"),
                                        ),
                                        NlaInt32(
                                            IFLA_GRE_LINK,
                                            saveas("gre_link"),
                                        ),
                                    )
                                ),
                                NlaIp4(
                                    IFLA_GRE_LOCAL,
                                    saveas("gre_local"),
                                ),
                                NlaIp4(
                                    IFLA_GRE_REMOTE,
                                    saveas("gre_remote"),
                                ),
                            ),
                            "ip6erspan": NlaNest(
                                IFLA_INFO_DATA,
                                *erspan_attrs,
                                NlaIp6(
                                    IFLA_GRE_LOCAL,
                                    saveas("gre_local"),
                                ),
                                NlaIp6(
                                    IFLA_GRE_REMOTE,
                                    saveas("gre_remote"),
                                ),
                            ),
                        },
                    )[getattr(accum, "kind")],
                ),
            ),
        )
    return list(
        nll_get_dump(
            RTM_GETLINK,
            RTM_NEWLINK,
            NlaStruct(ifinfomsg()).to_bytes(),
            lambda: LinkAccum(),
            parser.parse,
            sk=sk,
        )
    )


if __name__ == "__main__":
    from pprint import pprint

    try:
        pprint(
            link_add(
                name="myersp",
                up=True,
                kind="ip6erspan",
                gre_link=link_add(
                    name="myvrf",
                    up=True,
                    kind="vrf",
                    krt=999,
                ),
                erspan_ver=1,
                gre_ikey=1,
                gre_okey=1,
                gre_local="::1",
                gre_remote="::2",
            )
        )
        pprint(
            link_add(
                name="mydummy",
                up=True,
                kind="dummy",
            )
        )
    finally:
        pprint(list(get_links()))
        link_del(name="myersp")
        link_del(name="myvrf")
        link_del(name="mydummy")

    """
    from sys import argv
    from time import time

    full = len(argv) == 1
    nlinks = 5000

    if full or "setup" in argv:
        for i in range(nlinks):
            link_add(name=f"if{i}", kind="dummy")

    start = time()
    list(get_links())
    print(time() - start)

    if full or "cleanup" in argv:
        for i in range(nlinks):
            link_del(name=f"if{i}", kind="dummy")

    """
