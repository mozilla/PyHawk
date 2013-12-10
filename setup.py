#!/usr/bin/env python

import codecs
import os
from setuptools import setup


def read(*parts):
    return codecs.open(os.path.join(os.path.dirname(__file__), *parts)).read()

LONG_DESCRIPTION = """
Python libraries for the 'HAWK' HTTP authentication scheme

Hawk is an HTTP authentication scheme using a message authentication code
(MAC) algorithm to provide partial HTTP request cryptographic verification.

 https://github.com/hueniverse/hawk

PyHawk is great for consuming or providing webservices from Python.
"""


README = read('README.rst')
CHANGELOG = read('CHANGES.txt')

setup(
    name="PyHawk",
    version="0.1.3",
    url='https://github.com/mozilla/PyHawk',
    author='Austin King',
    author_email='ozten@mozilla.com',
    description="Python libraries for the 'HAWK' HTTP authentication scheme",
    long_description=LONG_DESCRIPTION,
    packages=['hawk', ],
    include_package_data=True,
    install_requires=['requests>=1.2.0'],
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    test_suite='hawk.tests',
)
