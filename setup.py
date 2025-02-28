import os

from setuptools import setup

setup(
    version=os.environ.get('VERSION', '0.0.0'),
)
