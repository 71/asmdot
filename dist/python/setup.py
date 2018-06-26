from setuptools import find_packages, setup
from configparser import ConfigParser

config = ConfigParser()
config.read('../../src/metadata.ini')

metadata = config['default']


setup(
    name            = metadata.get('name'),
    version         = metadata.get('version'),
    description     = metadata.get('description'),
    url             = metadata.get('url'),
    author          = metadata.get('author'),
    author_email    = metadata.get('author_email'),
    license         = 'MIT',

    python_requires = '>=3.6.0',

    packages             = find_packages(exclude=('tests',)),
    include_package_data = True,

    classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Assemblers'
    ]
)
