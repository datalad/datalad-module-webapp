from cherrypy.test import helper
from datalad.api import create
from datalad.api import webapp
from datalad.tests.utils import with_tempfile


class SimpleCPTest(helper.CPWebCase):
    @with_tempfile
    def setup_server(path):
        ds = create(path)
        webapp(
            'example_metadata',
            dataset=ds.path,
            mode='dry-run',
            hostsecret='dataladtest')

    setup_server = staticmethod(setup_server)

    def test_server_ok(self):
        # by default the beast is locked
        # unlock by visiting / with the correct secret
        self.getPage("/core/authenticate?datalad_host_secret=dataladtest")
        self.assertStatus('200 OK')
        self.getPage("/core/authenticate?datalad_host_secret=wrong")
        self.assertStatus('401 Unauthorized')
