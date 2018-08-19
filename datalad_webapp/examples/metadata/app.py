from os.path import dirname
from os.path import join as opj

import cherrypy
from cherrypy import tools

from datalad_webapp import verify_host_secret

cherrypy.tools.verify_datalad_hostsecret = cherrypy.Tool(
    'before_handler', verify_host_secret)


class MetadataAppExample(object):
    _webapp_component_dir = dirname(__file__)
    _webapp_component_staticdir = 'static'
    _webapp_component_config = opj(_webapp_component_dir, 'app.conf')

    def __init__(self, dataset):
        from datalad.distribution.dataset import require_dataset
        self.ds = require_dataset(
            dataset, check_installed=True, purpose='serving')

    @cherrypy.expose
    def index(self, datalad_host_secret=None):
        cherrypy.session['datalad_host_secret'] = datalad_host_secret
        from datalad_webapp import verify_host_secret
        verify_host_secret()
        return self.q()

    @cherrypy.expose
    @cherrypy.tools.verify_datalad_hostsecret()
    def q(self):
        return """<html>
          <head></head>
          <body>
            <form method="get" action="m">
              <input type="text" placeholder="relative path" name="path" />
              <button type="submit">Give me metadata!</button>
            </form>
          </body>
        </html>"""

    @cherrypy.expose
    @cherrypy.tools.verify_datalad_hostsecret()
    @tools.json_out()
    def m(self, path):
        from datalad.api import metadata
        return metadata(path, dataset=self.ds, result_renderer='disabled')

    @tools.json_out()
    @cherrypy.expose
    def config(self):
        import cherrypy
        return cherrypy.request.app.config
