#!/usr/bin/env python

import os.path as op
from setuptools import setup
from setuptools import find_packages


def get_version():
    # This might entail lots of imports which might not yet be available
    # so let's do ad-hoc parsing of the version.py
    with open(op.join(
            op.dirname(__file__),
            'datalad_webapp',
            '__init__.py')) as f:
        version_lines = list(filter(lambda x: x.startswith('__version__'), f))
    assert (len(version_lines) == 1)
    return version_lines[0].split('=')[1].strip(" '\"\t\n")


setup(
    # basic project properties can be set arbitrarily
    name="datalad_webapp",
    author="The DataLad Team and Contributors",
    author_email="team@datalad.org",
    version=get_version(),
    description="DataLad extension for exposing commands via a web request API",
    packages=[pkg for pkg in find_packages('.') if pkg.startswith('datalad')],
    # datalad command suite specs from here
    install_requires=[
        'datalad[full]>=0.12.0rc3',
        'flask',
        'flask-restful',
        'pytest-cov',
    ],
    entry_points = {
        'datalad.extensions': [
            'webapp=datalad_webapp:command_suite',
        ],
        # 'datalad.webapps' is THE entrypoint inspected by the datalad webapp command
        'datalad.webapp.resources': [
            # the label in front of '=' is the REST endpoint name
            # the entrypoint can point to any symbol of any name
            'auth=datalad_webapp.resources.auth:AuthenticationResource',
            'file=datalad_webapp.resources.file:FileResource',
            'subdataset=datalad_webapp.resources.subdataset:SubdatasetResource',
            'procedure=datalad_webapp.resources.procedure:ProcedureResource',
        ]
    },
)
