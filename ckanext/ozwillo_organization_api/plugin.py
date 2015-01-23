from hashlib import sha1
import hmac

import ckan.plugins as plugins
import ckan.logic as logic

from pylons import config
from ckan.common import request, _
from ckan.logic.action.create import _group_or_org_create as group_or_org_create

def valid_signature_required(func):
    plugin_config_prefix = 'ckanext.ozwillo_organization_api.'
    signature_header_name = config.get(plugin_config_prefix + 'signature_header_name',
                                       'X-Hub-Signature')
    instantiated_secret = config.get(plugin_config_prefix + 'instantiated_secret',
                                     'secret')

    def wrapper(context, data):
        if signature_header_name in request.headers:
            if request.headers[signature_header_name].startswith('sha1='):
                algo, hash = request.headers[signature_header_name].rsplit('=')
                computed_hash = hmac.new(instantiated_secret, str(data), sha1).hexdigest()
                if hash != computed_hash:
                    raise logic.NotAuthorized(_('Invalid HMAC'))
            else:
                raise logic.ValidationError(_('Invalid HMAC algo'))
        else:
            raise logic.NotAuthorized(_("No HMAC in the header"))
        return func(context, data)
    return wrapper

@valid_signature_required
def create_organization(context, data_dict):
    pass

@valid_signature_required
def delete_organization(context, data_dict):
    pass


class OzwilloOrganizationApiPlugin(plugins.SingletonPlugin):
    """
    API for OASIS to create and delete an organization
    """
    plugins.implements(plugins.IActions)

    def get_actions(self):
        return {
            'create-organization': create_organization,
            'delete-organization': delete_organization
        }
