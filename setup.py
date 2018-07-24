from setuptools import setup, find_packages


with open('requirements.txt', 'r') as f:
    requirements = f.readlines()

setup(
    name='npoed-sso-edx-client',
    version='1.0',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/miptliot/npoed-sso-edx-client',
    install_requires=requirements,
    packages=find_packages(exclude=['tests']),
)
