#!/usr/bin/env python

from setuptools import setup
from setuptools import find_packages

setup(
    # basic project properties can be set arbitrarily
    name="datalad_webapp",
    author="The DataLad Team and Contributors",
    author_email="team@datalad.org",
    version='0.1',
    description="DataLad extension for exposing commands via a web request API",
    packages=[pkg for pkg in find_packages('.') if pkg.startswith('datalad')],
    # datalad command suite specs from here
    install_requires=[
        # in general datalad will be a requirement, unless the datalad extension
        # aspect is an optional component of a larger project
        # disable for now as we currently need a Git snapshot (requirements.txt)
        #'datalad',
        'CherryPy',
    ],
    entry_points = {
        'datalad.extensions': [
            'webapp=datalad_webapp:command_suite',
        ],
        # 'datalad.webapps' is THE entrypoint inspected by the datalad webapp command
        'datalad.webapp.components': [
            # the label in front of '=' is the webapp component name
            # the entrypoint can point to any symbol of any name, as long it is
            # valid datalad interface specification
            'example_metadata=datalad_webapp.examples.metadata.app:MetadataAppExample',
        ]
    },
)
