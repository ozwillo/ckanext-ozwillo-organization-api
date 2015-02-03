from hashlib import sha1
import hmac
import requests
import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

import ckan.logic as logic

from pylons import config
from ckan.common import request, _
from ckan.logic.action.create import _group_or_org_create as group_or_org_create
from ckan.logic.action.create import user_create
from ckan.logic.action.delete import _group_or_org_purge

plugin_config_prefix = 'ckanext.ozwillo_organization_api.'

log = logging.getLogger(__name__)

def valid_signature_required(func):

    signature_header_name = config.get(plugin_config_prefix + 'signature_header_name',
                                       'X-Hub-Signature')
    instantiated_secret = config.get(plugin_config_prefix + 'instantiation_secret',
                                     'secret')

    def wrapper(context, data):
        if signature_header_name in request.headers:
            if request.headers[signature_header_name].startswith('sha1='):
                algo, received_hmac = request.headers[signature_header_name].rsplit('=')
                computed_hmac = hmac.new(instantiated_secret, request.body, sha1).hexdigest()
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
    context['ignore_auth'] = True
    model = context['model']

    destruction_secret = config.get(plugin_config_prefix + 'destruction_secret',
                                       'changeme')

    client_id = data_dict.pop('client_id')
    client_secret = data_dict.pop('client_secret')
    instance_id = data_dict.pop('instance_id')

    # re-mapping received dict
    registration_uri = data_dict.pop('instance_registration_uri')
    organization = data_dict['organization']
    user = data_dict['user']
    org_dict = {
        'type': 'organization',
        'name': organization['name'].lower(),
        'id': instance_id,
        'title': organization['name'],
        'description': organization['type'],
        'user': user['name']
    }

    user_dict = {
        'name': user['name'],
        'email': user['email_address'],
        'password': user['id']
    }
    user_obj = model.User.get(user_dict['name'])
    if not user_obj:
        user_create(context, user_dict)

    context['user'] = user_dict['name']

    try:
        delete_uri = toolkit.url_for(controller='api', action='action',
                                     logic_function="delete-organization",
                                     ver=context['api_version'],
                                     qualified=True)
        organization_uri = toolkit.url_for(host=request.host,
                                           controller='organization',
                                           action='read',
                                           id=org_dict['name'],
                                           qualified=True)


        group_or_org_create(context, org_dict, is_org=True)

        # setting organization as active explicitely
        group = model.Group.get(org_dict['name'])
        group.state = 'active'
        group.save()

        # notify about organization creation
        services = {'services': [{
            'local_id': 'organization',
            'name': 'Organization ' + org_dict['name'] + ' on CKAN',
            'service_uri': organization_uri,
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
    except Exception, e:
        log.debug('Exception "%s" occured while creating organization' % e)
        requests.delete(registration_uri)


@valid_signature_required
def delete_organization(context, data_dict):
    data_dict['id'] = data_dict.pop('instance_id')
    context['ignore_auth'] = True
    _group_or_org_purge(context, data_dict, is_org=True)


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
