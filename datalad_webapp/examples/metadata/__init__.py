import os.path as op

import cherrypy
from cherrypy import tools

from datalad_webapp.component import Component


class MetadataAppExample(Component):
    _webapp_component_dir = op.dirname(__file__)
    _webapp_component_config = op.join(_webapp_component_dir, 'app.conf')

    @cherrypy.expose
    @cherrypy.tools.datalad_verify_authentication()
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
    @cherrypy.tools.datalad_verify_authentication()
    @tools.json_out()
    def m(self, path):
        from datalad.api import metadata
        return metadata(path, dataset=self.ds, result_renderer='disabled')
