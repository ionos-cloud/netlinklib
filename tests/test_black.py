""" Unittest for black formatting check """

from glob import glob
from re import match
from subprocess import call
from unittest import TestCase, skipUnless
from pkg_resources import get_distribution, DistributionNotFound

version = [0]
try:
    version = [
        int(i)
        for i in match(r"([\d.]+)", get_distribution("black").version)[
            0
        ].split(".")
    ]
except DistributionNotFound:
    pass


@skipUnless(
    version >= [21, 10] and version < [24, 0], "black between 21.10 and 24.0"
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
