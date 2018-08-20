import os.path as op
import cherrypy
import uuid

from datalad_webapp.component import Component


class HostSecretComponent(Component):
    _webapp_component_dir = op.dirname(__file__)
    _webapp_component_config = op.join(_webapp_component_dir, 'component.conf')

    @staticmethod
    def verify_authentication():
        session_host_secret = cherrypy.session.get('datalad_host_secret', None)
        system_host_secret = cherrypy.config.get('datalad_host_secret', None)
        if not session_host_secret == system_host_secret:
            raise cherrypy.HTTPError(
                401,
                'Unauthorized session, please visit the URL shown at webapp startup')

    def __init__(self, dataset):
        super(HostSecretComponent, self).__init__(dataset=dataset)

        hostsecret = self.ds.config.get(
            'datalad.webapp.auth.hostsecret.secret',
            None)
        print('CFGSECRET', hostsecret)
        if hostsecret is None:
            hostsecret = uuid.uuid4()
            # little dance for python compat
            if hasattr(hostsecret, 'get_hex'):
                hostsecret = hostsecret.get_hex()
            else:
                hostsecret = hostsecret.hex
        cherrypy.config.update({
            'datalad_host_secret': hostsecret,
        })

    @cherrypy.expose
    def signin(self, secret=None):
        cherrypy.session['datalad_host_secret'] = secret
        HostSecretComponent.verify_authentication()

    def get_signin(self):
        return '/auth/hostsecret/signin?secret={}'.format(
            cherrypy.config['datalad_host_secret'])
