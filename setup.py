# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

try:
    with open('README.md') as f:
        long_description = f.read()
except IOError:
    long_description = ''

setup(
    name='cergen',
    version='0.2.5',
    description='Automated x509 certificate generation and management',
    license='Apache',
    author='Andrew Otto',
    packages=find_packages(),
    python_requires='>=3',
    setup_requires=['pytest-runner', 'setuptools_scm < 2.0.0'],
    tests_require=['pytest'],
    install_requires=[
        'docopt>=0.6',
        'python-dateutil>=2.5.0',
        'pyyaml>=3',
        'cryptography',
        # networkx released 2.x in September 2017.
        # We want a version with Debian packages (in component/cergen)
        'networkx<2.0',
        'requests>=2',
        'pyOpenSSL',
        # Also need installed
        # python3-dev
        # libffi-dev
        # libssl-dev
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
