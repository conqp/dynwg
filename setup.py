#! /usr/bin/env python
"""Installation script."""

from setuptools import setup

setup(
    name="dynwg",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    author="Richard Neumann",
    author_email="mail@richard-neumann.de",
    python_requires=">=3.8",
    py_modules=["dynwg"],
    entry_points={"console_scripts": ["dynwg = dynwg:main"]},
    data_files=[("/usr/lib/systemd/system", ["dynwg.service", "dynwg.timer"])],
    url="https://github.com/conqp/dynwg",
    license="GPLv3",
    description=(
        "A simple, lightweight DynDNS watchdog for " "WireGuard via systemd-networkd."
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    keywords="dynamic wireguard wg watchdog resolve reresolve",
)
