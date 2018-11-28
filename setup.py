import os
from os.path import join, dirname, split
#from distutils.core import setup
from setuptools import setup, find_packages


setup(
    name='tp-sso-edx-client',
    version='1.0',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/dorosh/edx-sso-npoed',
    
    packages=find_packages(exclude=['tests']),
)
