"""Unittest for black formatting check"""

from glob import glob
from re import match
from subprocess import call
from unittest import TestCase, skipUnless
from pkg_resources import get_distribution, DistributionNotFound
from . import no_less_than

black_version = "0.0"
try:
    vermatch = match(r"[\.\d]*", get_distribution("black").version)
    if vermatch is not None:
        black_version = vermatch.group()
except DistributionNotFound:
    pass

# Black is broken in later point-releases of bullseye.
# If import fails, skip the test
try:
    import black  # pylint: disable=unused-import  # noqa: F401

    RUN_TEST = True
except ImportError:
    RUN_TEST = False


@skipUnless(RUN_TEST, "black broken in bullseye distro")
@skipUnless(
    no_less_than("24")(black_version), "black 24.0 and up is acceptable"
)
class BlackTest(TestCase):
    """Class for back formatting check"""

    def test_run_black(self):
        result = call(
            [
                "black",
                "--check",
                "--diff",
                "-l",
                "79",
            ]
            + glob("mknetlinkdefs/**/*.py", recursive=True)
            + glob("netlinklib/**/*.py", recursive=True)
            + glob("tests/**/*.py", recursive=True)
        )
        self.assertEqual(result, 0, "black formatting")
