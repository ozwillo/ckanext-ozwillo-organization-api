from hashlib import sha1
import hmac

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

import ckan.logic as logic

from pylons import config
from ckan.common import request, _
from ckan.logic.action.create import _group_or_org_create as group_or_org_create

plugin_config_prefix = 'ckanext.ozwillo_organization_api.'

def valid_signature_required(func):

    signature_header_name = config.get(plugin_config_prefix + 'signature_header_name',
                                       'X-Hub-Signature')
    instantiated_secret = config.get(plugin_config_prefix + 'instantiated_secret',
                                     'secret')

    def wrapper(context, data):
        if signature_header_name in request.headers:
            if request.headers[signature_header_name].startswith('sha1='):
                algo, received_hmac = request.headers[signature_header_name].rsplit('=')
                computed_hmac = hmac.new(instantiated_secret, str(data), sha1).hexdigest()
                # the received hmac is uppercase according to
                # http://doc.ozwillo.com/#ref-3-2-1
                if received_hmac != computed_hmac.upper():
                    raise logic.NotAuthorized(_('Invalid HMAC'))
            else:
                raise logic.ValidationError(_('Invalid HMAC algo'))
        else:
            raise logic.NotAuthorized(_("No HMAC in the header"))
        return func(context, data)
    return wrapper

@valid_signature_required
def create_organization(context, data_dict):

    destruction_secret = config.get(plugin_config_prefix + 'destruction_secret',
                                       'changeme')

    client_id = data_dict.pop('client_id')
    client_secret = data_dict.pop('client_secret')
    instance_id = data_dict.pop('instance_id')

    # re-mapping received dict
    registration_uri = data_dict.pop('instance_registration_uri')
    organization = data_dict['organization']
    org_dict = {
        'type': 'organization',
        'name': organization['organization_name'].lower(),
        'id': instance_id,
        'title': organization['organization_name'],
        'description': organization['type'],
    }
    try:
        delete_uri = toolkit.url_for(controller='api', action='action',
                                     logic_function="delete-organization",
                                     ver=context['api_version'],
                                     qualified=True)

        group_or_org_create(context, org_dict, is_org=True)

        # notify about organization creation
        services = {'services': [{
            'local_id': 'organization',
            'name': 'Organization ' + org_dict['name'] + ' on CKAN',
            'service_uri': '/organization/' + org_dict['name'],
            'visible': True}],
            'instance_id': instance_id,
            'destruction_uri': delete_uri,
            'destruction_secret': destruction_secret,
            'needed_scopes': [{
                'scope_id': 'profile',
                'motivation': 'Used to link user to the organization'
            }]
        }
        requests.post(registration_uri,
                      data = services,
                      auth=(client_id, client_secret)
                  )
    except:
        request.delete(registration_uri)


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
            'create-ozwillo-organization': create_organization,
            'delete-ozwillo-organization': delete_organization
        }
