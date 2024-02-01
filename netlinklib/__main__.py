""" Manual test for netlinklib """

from cProfile import Profile
from pstats import Stats
from time import time
from . import nll_get_links, nll_get_routes, nll_get_neigh

if __name__ == "__main__":
    before = time()
    with Profile() as profile:
        links = list(nll_get_links())
        profile.create_stats()
        Stats(profile).strip_dirs().sort_stats("time").print_stats(10)
    after = time()
    print("links", len(links), after - before)
    before = time()
    with Profile() as profile:
        links = list(nll_get_links(nameonly=True))
        profile.create_stats()
        Stats(profile).strip_dirs().sort_stats("time").print_stats(10)
    after = time()
    print("links(nameonly)", len(links), after - before)
    before = time()
    with Profile() as profile:
        routes = list(nll_get_routes())
        profile.create_stats()
        Stats(profile).strip_dirs().sort_stats("time").print_stats(10)
    after = time()
    print("routes", len(routes), after - before)
    before = time()
    with Profile() as profile:
        neighs = list(nll_get_neigh())
        profile.create_stats()
        Stats(profile).strip_dirs().sort_stats("time").print_stats(10)
    after = time()
    print("neighs", len(neighs), after - before)
