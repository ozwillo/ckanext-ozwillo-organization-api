from hashlib import sha1
import hmac
import requests
import logging
import json

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
    session = context['session']

    destruction_secret = config.get(plugin_config_prefix + 'destruction_secret',
                                       'changeme')

    client_id = data_dict.pop('client_id')
    client_secret = data_dict.pop('client_secret')
    instance_id = data_dict.pop('instance_id')

    # re-mapping received dict
    registration_uri = data_dict.pop('instance_registration_uri')
    organization = data_dict['organization']
    user = data_dict['user']
    user_dict = {
        'name': user['name'].lower().replace(' ', ''),
        'email': user['email_address'],
        'password': user['id']
    }
    user_obj = model.User.get(user_dict['name'])

    org_dict = {
        'type': 'organization',
        'name': organization['name'].lower().replace(' ', '-'),
        'id': instance_id,
        'title': organization['name'],
        'description': organization['type'],
        'user': user_dict['name']
    }

    if not user_obj:
        user_create(context, user_dict)
    context['user'] = user_dict['name']

    try:
        delete_uri = toolkit.url_for(host=request.host,
                                     controller='api', action='action',
                                     logic_function="delete-ozwillo-organization",
                                     ver=context['api_version'],
                                     qualified=True)
        organization_uri = toolkit.url_for(host=request.host,
                                           controller='organization',
                                           action='read',
                                           id=org_dict['name'],
                                           qualified=True)
        default_icon_url = toolkit.url_for(host=request.host,
                                           qualified=True,
                                           controller='home',
                                           action='index') + 'organization_icon.png'

        group_or_org_create(context, org_dict, is_org=True)

        # setting organization as active explicitely
        group = model.Group.get(org_dict['name'])
        group.state = 'active'
        group.image_url = default_icon_url
        group.save()
        model.repo.new_revision()
        model.GroupExtra(group_id=group.id, key='client_id',
                         value=client_id).save()
        model.GroupExtra(group_id=group.id, key='client_secret',
                         value=client_secret).save()
        session.flush()

        # notify about organization creation
        services = {'services': [{
            'local_id': 'organization',
            'name': org_dict['title'],
            'service_uri': organization_uri + '/sso',
            'description': 'Organization ' + org_dict['name'] + ' on CKAN',
            'tos_uri': organization_uri,
            'policy_uri': organization_uri,
            'icon': group.image_url,
            'payment_option': 'FREE',
            'target_audience': ['PUBLIC_BODIES'],
            'contacts': [organization_uri],
            'redirect_uris': [organization_uri + '/callback'],
            'visible': True}],
            'instance_id': instance_id,
            'destruction_uri': delete_uri,
            'destruction_secret': destruction_secret,
            'needed_scopes': [{
                'scope_id': 'profile',
                'motivation': 'Used to link user to the organization'
            }]
        }
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        requests.post(registration_uri,
                      data=json.dumps(services),
                      auth=(client_id, client_secret),
                      headers=headers
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
    plugins.implements(plugins.IConfigurer)

    def update_config(self, config):
        toolkit.add_public_directory(config, 'public')

    def get_actions(self):
        return {
            'create-ozwillo-organization': create_organization,
            'delete-ozwillo-organization': delete_organization
        }
