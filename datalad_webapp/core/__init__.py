import os.path as op
import cherrypy

from datalad_webapp.component import Component


def verify_host_secret():
    session_host_secret = cherrypy.session.get('datalad_host_secret', None)
    system_host_secret = cherrypy.config.get('datalad_host_secret', None)
    if not session_host_secret == system_host_secret:
        raise cherrypy.HTTPError(
            401,
            'Unauthorized session, please visit the URL shown at webapp startup')


cherrypy.tools.datalad_verify_authentication = cherrypy.Tool(
    'before_handler', verify_host_secret)


class CoreComponent(Component):
    _webapp_component_dir = op.dirname(__file__)
    _webapp_component_config = op.join(_webapp_component_dir, 'component.conf')

    @cherrypy.expose
    def authenticate(self, datalad_host_secret=None):
        cherrypy.session['datalad_host_secret'] = datalad_host_secret
        verify_host_secret()
