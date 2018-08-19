from cherrypy.test import helper
from datalad.api import create
from datalad.api import webapp
from datalad.tests.utils import with_tempfile


class SimpleCPTest(helper.CPWebCase):
    @with_tempfile
    def setup_server(path):
        ds = create(path)
        ds.config.set(
            'datalad.webapp.auth.hostsecret.secret',
            'dataladtest',
            where='dataset')
        webapp(
            'example_metadata',
            dataset=ds.path,
            mode='dry-run',
            auth='hostsecret')

    setup_server = staticmethod(setup_server)

    def test_server_ok(self):
        # by default the beast is locked
        # unlock by visiting / with the correct secret
        self.getPage("/auth/hostsecret/signin?secret=dataladtest")
        self.assertStatus('200 OK')
        self.getPage("/auth/hostsecret/signin?secret=wrong")
        self.assertStatus('401 Unauthorized')
