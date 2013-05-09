#!/usr/bin/env python
from setuptools import setup

requires = ['requests>=1.2.0', ]

README = open('README.rst').read()
CHANGELOG = open('CHANGES.txt').read()


setup(
    name="PyHawk",
    version="0.1",
    url='https://github.com/mozilla/PyHawk',
    author='The Mozilla Fundation',
    author_email='ozten@mozilla.com',
    description="",
    long_description=README + '\n' + CHANGELOG,
    packages=['hawk', ],
    include_package_data=True,
    install_requires=requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    test_suite='hawk.tests',
)
