from __future__ import division, absolute_import
from setuptools import setup, find_packages


setup(
    name='journal2gelf',
    version='2.0.0',
    description='Export structured log records from a systemd journal and send them to a graylog server.',
    url='https://github.com/nailgun/journal2gelf',
    author='Nailgun',
    author_email='dbashkatov@gmail.com',
    license='MIT',
    packages=find_packages(),

    entry_points={
        'console_scripts': [
            'journal2gelf = journal2gelf:main',
        ],
    },
)
