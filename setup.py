#!/usr/bin/env python

import codecs
import os
from setuptools import setup


def read(*parts):
    return codecs.open(os.path.join(os.path.dirname(__file__), *parts)).read()

README = read('README.rst')
CHANGELOG = read('CHANGES.txt')

setup(
    name="PyHawk",
    version="0.1.0",
    url='https://github.com/mozilla/PyHawk',
    author='Austin King',
    author_email='ozten@mozilla.com',
    description=README,
    long_description=README + '\n' + CHANGELOG,
    packages=['hawk', ],
    include_package_data=True,
    install_requires=['requests>=1.2.0', 'pycrypto==2.6'],
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
