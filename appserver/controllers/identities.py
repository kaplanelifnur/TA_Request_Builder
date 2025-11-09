from splunk.appserver.mrsparkle.controllers.base import BaseController
from splunk.appserver.mrsparkle.lib.routes import route
import cherrypy

class IdentitiesController(BaseController):

    @route('/identities')
    @cherrypy.expose
    def identities(self, **kwargs):
        return self.render_template('identities.html')
