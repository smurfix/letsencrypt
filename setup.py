#!/usr/bin/python3

import codecs
import os
import re

import setuptools

def read_version():
    regexp = re.compile(r"^__version__\W*=\W*'([\d.]+)'")
    init_py = os.path.join(os.path.dirname(__file__), 'lets_enc', '__init__.py')
    with open(init_py) as fp:
        for line in fp:
            match = regexp.match(line)
            if match is not None:
                return match.group(1)
        else:
            raise RuntimeError('Cannot find version in callme/__init__.py')

setuptools.setup(
    name="lets_enc",
    version=read_version(),
    packages=setuptools.find_packages(),
    install_requires=['Crypto'],

    # metadata for upload to PyPI
    author="Matthias Urlichs",
    author_email="matthias@urlichs.de",
    description="Simple Let's Encrypt client",
    keywords="letsencrypt",
    platforms=["any"],
    url="http://packages.python.org/letsenc",
    license='GPLv2',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
    ],
    zip_safe=True,
)
