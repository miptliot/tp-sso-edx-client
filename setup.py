from setuptools import setup, find_packages


setup(
    name='tp-sso-edx-client',
    version='1.0',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/miptliot/tp-sso-edx-client',
    packages=find_packages(exclude=['tests']),
)
