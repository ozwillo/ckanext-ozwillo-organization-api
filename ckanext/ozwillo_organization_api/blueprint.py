# Migrate controllers to Flask blueprints, required for python3 https://github.com/ckan/ckan/issues/4791

from flask import Blueprint
from flask.views import MethodView

ozwillo_organization_api = Blueprint(u'ozwillo_organization_api', __name__)

class ErrorView(MethodView): # like in ckan/ckanext/datapusher/blueprint.py
    def error403(self):
        return base.abort(403, '')

# disable organization and members api
for action in ('member_create', 'member_delete',
               'organization_member_delete',
               'organization_member_create',
               'organization_create',
               'organization_update',
               'organization_delete'):
  ozwillo_organization_api.add_url_rule(
      '/api/{ver:.*}/action/%s' % action,
                          view_func=ErrorView.error403) #as_view(str(action))
