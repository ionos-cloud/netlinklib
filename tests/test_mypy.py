from os import environ
from subprocess import call
from unittest import TestCase, skipUnless, main
from typing import List
from pkg_resources import get_distribution, DistributionNotFound

mypy_version = 0
try:
    mypy_version = [
        int(x) for x in get_distribution("mypy").version.split(".")[:2]
    ]
except DistributionNotFound:
    pass

WHATTOCHECK = ["netlinklib"]


class TypeCheckTest(TestCase):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mypy_env: List[str] = environ.copy()
        # self.mypy_env.update({"MYPYPATH": "mypystubs"})
        self.mypy_opts: List[str] = ["--strict"]

    @skipUnless(mypy_version > [0, 971], "Do not trust earlier mypy versions")
    def test_run_mypy(self):
        mypy_call: List[str] = ["mypy"] + self.mypy_opts + WHATTOCHECK
        result: int = call(mypy_call, env=self.mypy_env)
        self.assertEqual(result, 0, "mypy typecheck")


if __name__ == "__main__":
    main()
