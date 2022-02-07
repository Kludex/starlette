#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re

from setuptools import setup, find_packages


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    with open(os.path.join(package, "__init__.py")) as f:
        return re.search("__version__ = ['\"]([^'\"]+)['\"]", f.read()).group(1)


def get_long_description():
    """
    Return the README.
    """
    with open("README.md", encoding="utf8") as f:
        return f.read()


setup(
    name="starlette",
    python_requires=">=3.6",
    version=get_version("starlette"),
    url="https://github.com/encode/starlette",
    license="BSD",
    description="The little ASGI library that shines.",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Tom Christie",
    author_email="tom@tomchristie.com",
    packages=find_packages(exclude=["tests*"]),
    package_data={"starlette": ["py.typed"]},
    include_package_data=True,
    install_requires=[
        "anyio>=3.4.0,<4",
        "typing_extensions>=3.10.0; python_version < '3.10'",
        "contextlib2 >= 21.6.0; python_version < '3.7'",
    ],
    extras_require={
        "full": [
            "itsdangerous",
            "jinja2",
            "python-multipart",
            "pyyaml",
            "requests",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP",
        "Framework :: AnyIO",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    zip_safe=False,
)
