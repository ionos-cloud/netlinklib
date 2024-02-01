from os import getcwd, chdir
from re import findall
from setuptools import setup
from subprocess import call


def pep_version(s: str) -> str:
    """Take initial numeric part from the string, to comply with PEP-440"""
    return "0.1"
    for i in range(0, len(s)):
        if not s[i] in "0123456789.":
            break
    return s[:i].rstrip(".")


with open("debian/changelog", "r") as clog:
    _, version, _ = findall(
        r"(?P<src>.*) \((?P<version>.*)\) (?P<suite>.*); .*",
        clog.readline().strip(),
    )[0]

print("Building a definitions file")
curdir = getcwd()
chdir("mknetlinkdefs")
result = call(["make"])
if result:
    raise RuntimeError(f"make failed with result={result}")
chdir(curdir)

print(f"configuring package with version {pep_version(version)}")
setup(
    name="netlinklib",
    version=pep_version(version),
    description="Higher performance netlink library",
    author="Eugene Crosser",
    author_email="evgenii.cherkashin@ionos.com",
    packages=["netlinklib"],
    package_data={'netlinklib': ["py.typed"]},
    tests_require=["black", "pylint", "mypy"],
)
