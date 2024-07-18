""" Manual test for netlinklib """

from typing import Any, Literal
from cProfile import Profile
from pstats import Stats
from time import time
from . import nll_get_links, nll_get_routes, nll_get_neigh


class profiling:  # pylint: disable=invalid-name
    """Profiling context manager"""

    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self) -> None:
        # pylint: disable=attribute-defined-outside-init
        self.prof = Profile()
        self.before = time()
        self.prof.enable()

    def __exit__(self, *_: Any) -> Literal[False]:
        after = time()
        self.prof.create_stats()
        Stats(self.prof).strip_dirs().sort_stats("time").print_stats(8)
        self.prof.disable()
        print("time used for", self.name, ":", after - self.before)
        return False


if __name__ == "__main__":
    with profiling("nll_get_links"):
        links = list(nll_get_links())
    print("links", len(links))
    with profiling("nll_get_links(nameonly)"):
        links = list(nll_get_links(nameonly=True))
    print("links", len(links))
    with profiling("nll_get_routes"):
        routes = list(nll_get_routes())
    print("routes", len(routes))
    with profiling("nll_get_neigh"):
        neighs = list(nll_get_neigh())
    print("neighs", len(neighs))
