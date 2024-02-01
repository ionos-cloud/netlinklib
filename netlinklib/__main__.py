""" Manual test for netlinklib """

from time import time
from . import nll_get_links, nll_get_routes, nll_get_neigh

if __name__ == "__main__":
    before = time()
    links = list(nll_get_links())
    after = time()
    print("links", len(links), "\n", after - before)
    before = time()
    links = list(nll_get_links(nameonly=True))
    after = time()
    print("links(nameonly)", len(links), "\n", after - before)
    before = time()
    routes = list(nll_get_routes())
    after = time()
    print("routes", len(routes), "\n", after - before)
    before = time()
    neighs = list(nll_get_neigh())
    after = time()
    print("neighs", len(neighs), "\n", after - before)
