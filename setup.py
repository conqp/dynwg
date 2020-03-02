#! /usr/bin/env python

from setuptools import setup

setup(
    name='dynwg',
    version='1.1.1',
    author='Richard Neumann',
    author_email='mail@richard-neumann.de',
    python_requires='>=3.8',
    py_modules=['dynwg'],
    scripts=['dynwg'],
    data_files=[
        ('/usr/lib/systemd/system', ['dynwg.service', 'dynwg.timer'])
    ],
    url='https://github.com/conqp/dynwg',
    license='GPLv3',
    description=(
        'A simple, lightweight DynDNS watchdog for '
        'WireGuard via systemd-networkd.'),
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    keywords='dynamic wireguard wg watchdog resolve reresolve'
)
