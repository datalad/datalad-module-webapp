# emacs: -*- mode: python; py-indent-offset: 4; tab-width: 4; indent-tabs-mode: nil -*-
# ex: set sts=4 ts=4 sw=4 noet:
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
#
#   See COPYING file distributed along with the datalad package for the
#   copyright and license terms.
#
# ## ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ##
"""Component base class"""

__docformat__ = 'restructuredtext'

import logging

lgr = logging.getLogger('datalad.webapp.component')


class Component(object):
    _webapp_component_staticdir = 'static'
    _webapp_component_config = None

    def __init__(self, dataset):
        self.ds = dataset
