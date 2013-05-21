#!/usr/bin/env python

import codecs
import os
import re
from setuptools import setup


def read(*parts):
    return codecs.open(os.path.join(os.path.dirname(__file__), *parts)).read()

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


README = read('README.rst')
CHANGELOG = read('CHANGES.txt')

setup(
    name="PyHawk",
    version=find_version('hawk/__init__.py'),
    url='https://github.com/mozilla/PyHawk',
    author='Austin King',
    author_email='ozten@mozilla.com',
    description=README,
    long_description=README + '\n' + CHANGELOG,
    packages=['hawk', ],
    include_package_data=True,
    install_requires=['requests>=1.2.0', ],
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
