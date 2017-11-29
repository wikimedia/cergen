# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

try:
    with open('README.md') as f:
        long_description = f.read()
except IOError:
    long_description = ''

setup(
    name='cergen',
    version='0.1.0',
    description='Automated x509 certificate generation and management',
    license='Apache',
    author='Andrew Otto',
    packages=find_packages(),
    python_requires='>=3',
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    install_requires=[
        'docopt>=0.6',
        'pyyaml>=3',
        'cryptography>=1.7.0,<2.0.0',
        # networkx released 2.x in September 2017.
        # We want a version with Debian packages.
        'networkx<2.0',
        'requests>=2',
        'pyOpenSSL>=16.0.0'
        # Also need installed
        # python3-dev
        # libffi-dev
    ],
    long_description=long_description,
    entry_points={'console_scripts': ['cergen = cergen.main:main']},
    scripts=[
        'ext/puppet-sign-cert'
    ],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
    ]
)
