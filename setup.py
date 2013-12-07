from setuptools import setup, find_packages

import iceit

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup_options = dict(
    name='iceit',
    version=iceit.__version__,
    description='Backup your files to Amazon Glacier.',
    long_description=open('README.md').read(),
    author='boosh',
    scripts=['bin/iceit'],
    packages=find_packages('.', exclude=['tests*']),
    package_dir={'iceit': 'iceit'},
    install_requires=required,
    license="MIT",
    classifiers=(
        'Natural Language :: English',
        'Programming Language :: Python',
        ),
)

setup(**setup_options)