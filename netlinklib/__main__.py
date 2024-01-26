""" Manual test for netlinklib """

from time import time
from . import nll_get_links, nll_get_routes

if __name__ == "__main__":
    before = time()
    links = list(nll_get_links())
    after = time()
    print(links, "\n", len(links), "\n", after - before)
    before = time()
    routes = list(nll_get_routes())
    after = time()
    print(routes, "\n", len(routes), "\n", after - before)
