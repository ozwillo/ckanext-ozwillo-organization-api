from hashlib import sha1
import hmac
import requests
import logging
import json
import re
from slugify import slugify

import ckan.plugins as plugins
from ckan.plugins.toolkit import redirect_to, request, config, add_template_directory, add_public_directory, get_action #, BaseController
from ckan.lib.helpers import url_for

toolkit = plugins.toolkit

import ckan.model as model

from ckan.common import _, c
from ckan.logic.action.create import _group_or_org_create as group_or_org_create
from ckan.logic.action.create import user_create
from ckan.logic.action.delete import _group_or_org_purge
from ckan.lib.plugins import DefaultOrganizationForm

from ckanext.ozwillo_organization_api import blueprint

plugin_config_prefix = 'ckanext.ozwillo_organization_api.'

log = logging.getLogger(__name__)


def valid_signature_required(secret_prefix):

    signature_header_name = config.get(plugin_config_prefix + 'signature_header_name', 'X-Hub-Signature')
    api_secret = config.get(plugin_config_prefix + secret_prefix + '_secret', 'secret')

    def decorator(func):
        def wrapper(context, data):
            if signature_header_name in request.headers:
                if request.headers[signature_header_name].startswith('sha1='):
                    algo, received_hmac = request.headers[signature_header_name].rsplit('=')
                    # since python 3, bytes are not directly str so key must be encoded : https://stackoverflow.com/a/43882903/2862821
                    # else ERROR [ckan.views.api] key: expected bytes or bytearray, but got 'str'
                    computed_hmac = hmac.new(bytes(api_secret, 'utf-8'), request.get_data(), sha1).hexdigest()
                    if received_hmac.lower() != computed_hmac:
                        log.info('Invalid HMAC')
                        raise toolkit.NotAuthorized(_('Invalid HMAC'))
                else:
                    log.info('Invalid HMAC algo')
                    raise toolkit.ValidationError(_('Invalid HMAC algo'))
            else:
                log.info('No HMAC in the header')
                raise toolkit.NotAuthorized(_("No HMAC in the header"))
            return func(context, data)
        return wrapper
    return decorator


@valid_signature_required(secret_prefix='instantiation')
def create_organization(context, data_dict):
    context['ignore_auth'] = True
    model = context['model']
    session = context['session']

    destruction_secret = config.get(plugin_config_prefix + 'destruction_secret', 'changeme')

    client_id = data_dict.pop('client_id')
    client_secret = data_dict.pop('client_secret')
    instance_id = data_dict.pop('instance_id')

    # re-mapping received dict
    registration_uri = data_dict.pop('instance_registration_uri')
    organization = data_dict['organization']

    log.info('Creating organization {} (instance id : {})'.format(organization, instance_id))

    user = data_dict['user']
    user_dict = {
        'id': user['id'],
        'name': user['id'].replace('-', ''),
        'email': user['email_address'],
        'password': user['id']
    }
    user_obj = model.User.get(user_dict['name'])

    org_dict = {
        'type': 'organization',
        'name': slugify(organization['name']),
        'id': instance_id,
        'title': organization['name'],
        'user': user_dict['name']
    }

    if not user_obj:
        user_create(context, user_dict)
    context['user'] = user_dict['name']

    try:
        delete_uri = url_for(controller='api',
                             action='action',
                             logic_function='delete-ozwillo-organization',
                             ver=context['api_version'],
                             qualified=True)
        organization_uri = url_for(controller='organization',
                                   action='read',
                                   id=org_dict['name'],
                                   qualified=True)
        default_icon_url = url_for(controller='home',
                                   action='index',
                                   qualified=True) + 'opendata.png'

        group_or_org_create(context, org_dict, is_org=True)

        # setting organization as active explicitly
        group = model.Group.get(org_dict['name'])
        group.state = 'active'
        group.image_url = default_icon_url
        group.save()
        # no model.repo.new_revision() in 2.9 like in 2.8.2, see ckan/action/create.py diff & https://pythonrepo.com/repo/ckan-ckan-python-science
        model.GroupExtra(group_id=group.id, key='client_id',
                         value=client_id).save()
        model.GroupExtra(group_id=group.id, key='client_secret',
                         value=client_secret).save()

        # Automatically add data from data gouv
        dc_id = data_dict['organization']['dc_id']
        siret_re = re.compile(r'\d{14}')
        try:
            organization_insee = siret_re.search(dc_id).group()
            after_create(group, organization_insee, user_dict['name'])
        except AttributeError:
            log.info('SIRET did not match pattern, no data will be added')

        session.flush()

        # notify about organization creation
        services = {'services': [{
            'local_id': 'organization',
            'name': 'Open Data - ' + org_dict['title'],
            'service_uri': organization_uri + '/sso',
            'description': 'Organization ' + org_dict['name'] + ' on CKAN',
            'tos_uri': organization_uri,
            'policy_uri': organization_uri,
            'icon': group.image_url,
            'payment_option': 'FREE',
            'target_audience': ['PUBLIC_BODIES', 'CITIZENS', 'COMPANIES'],
            'contacts': [organization_uri],
            'redirect_uris': [organization_uri + '/callback'],
            'post_logout_redirect_uris': [organization_uri + '/logout'],
            'visible': False}],
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

        log.info('Confirming registration on {}'.format(registration_uri))
        services_copy = services.copy()
        del services_copy['destruction_secret']
        log.info('Registration info is {}'.format(json.dumps(services_copy)))

        registration_response = requests.post(registration_uri,
                      data=json.dumps(services),
                      auth=(client_id, client_secret),
                      headers=headers)
        log.debug('Received response from kernel : {} ({})'.format(registration_response.text, registration_response.status_code))
    except toolkit.ValidationError as e:
        log.debug('Validation error "%s" occurred while creating organization' % e)
        raise


@valid_signature_required(secret_prefix='destruction')
def delete_organization(context, data_dict):
    data_dict['id'] = data_dict.pop('instance_id')
    context['ignore_auth'] = True
    _group_or_org_purge(context, data_dict, is_org=True)


class OrganizationForm(plugins.SingletonPlugin, DefaultOrganizationForm):
    """
    Custom form ignoring 'title' and 'name' organization fields
    """
    plugins.implements(plugins.IGroupForm)

    def is_fallback(self):
        return False

    def group_types(self):
        return ('organization',)

    def group_controller(self):
        return 'organization'

    def form_to_db_schema(self):
        schema = super(OrganizationForm, self).form_to_db_schema()
        del schema['name']
        del schema['title']
        return schema


class OzwilloOrganizationApiPlugin(plugins.SingletonPlugin):
    """
    API for OASIS to create and delete an organization
    """
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)

    def get_blueprint(self):
        return blueprint.ozwillo_organization_api

    def before_map(self, map):
        return map

    def after_map(self, map):
        return map

    def update_config(self, config):
        add_template_directory(config, 'templates')
        add_public_directory(config, 'public')

    def get_actions(self):
        return {
            'create-ozwillo-organization': create_organization,
            'delete-ozwillo-organization': delete_organization
        }


# Used for tests purposes
class CreateOrganizationPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.interfaces.IOrganizationController, inherit=True)

    def create(self, entity):
        after_create(entity, '21620516100013', 'user')


def after_create(entity, organization_siret, user):
    '''
    This method is called after a new instance is created.
    It uses the services from data.gouv.fr to automatically add data to our new instance.
    It is possible to add automatically any other resources from different services as
    long as an api returns the desired resources urls.

    :param entity: object, the organization being created
    :param organization_siret: string, the siret of the organization being created.
    :return:
    '''

    try:
        name_from_siret = get_name_from_siret(organization_siret)
        log.info("Got name {} from SIRET {}".format(name_from_siret, organization_siret))
        if name_from_siret is None:
            raise ValueError
        organization = slugify(name_from_siret)
        if organization is None:
            raise ValueError
        log.info("Slugified organization is {}".format(organization))
    except (ValueError, requests.ConnectionError) as e:
        log.error('No organization found for this SIRET, no data will be added : {}'.format(e))
        return

    organization_id = entity.id
    insee_re = re.compile(r'\d{5}')
    base_url_1 = 'https://www.data.gouv.fr/api/1/territory/suggest/?q='
    base_url_2 = 'https://www.data.gouv.fr/api/1/spatial/zone/{}/datasets?'

    try:
        # Get the city from the gouv api and extract the name, id, description and insee
        city_response = requests.get(base_url_1 + organization)
        city_json = city_response.json()
        city_name = slugify(city_json[0]['title'])
        city_description = city_json[0]['page']
        city_id = city_json[0]['id']
        city_insee = insee_re.search(city_id).group()
        log.info(city_name)
    except (ValueError, AttributeError, KeyError, IndexError, requests.exceptions.RequestException) as e:
        log.error('No territory found for this organization, no data will be added : {}'.format(e))
        return

    # Get the dataset dict with the 9 dynamic datasets
    dataset_dict = setup_dataset_dict(city_insee)

    # Create the datasets and resources from the dataset_dict in our previously created dataset
    resource_count = 0
    for key, value in dataset_dict.items():
        package_data = {'name': slugify(organization + '-' + key),
                        'private': 'false',
                        'owner_org': organization_id,
                        'notes': city_description,
                        'tags': [{'name': 'auto-import'}]}
        try:
            context = {'model': model, 'session': model.Session,
                       'user': user, 'return_id_only': 'true'}
            package_id = get_action('package_create')(context, package_data)
            gouv_resource = {'package_id': package_id,
                             'url': value,
                             'name': key}
            get_action('resource_create')(context, gouv_resource)
            resource_count += 1
        except Exception as err:
            log.info(err)

    # Get the others non dynamic urls from the data gouv api
    try:
        city_datasets = requests.get(base_url_2.format(city_id))
        dataset_json = city_datasets.json()
    except (ValueError, AttributeError, KeyError, IndexError, requests.exceptions.RequestException) as e:
        log.error('No datasets found for this organization, no data will be added to the dataset : {}'.format(e))
        return

    # For the other datasets, create a local dataset linked to the datagouv one after checking they are valid
    for dataset in dataset_json:
        try:
            response = requests.get(dataset['uri'])
            if response.status_code == 404:
                continue
            else:
                context = {'model': model, 'session': model.Session, 'user': user}
                package_data = {'name': slugify(organization + '_' + dataset['title']),
                                'private': 'false',
                                'owner_org': organization_id,
                                'notes': city_description,
                                'url': dataset['uri'],
                                'tags': [{'name': 'auto-import'}]}
                get_action('package_create')(context, package_data)
                resource_count += 1
        except (ValueError, AttributeError, KeyError, IndexError, requests.exceptions.RequestException) as e:
            log.error('No resources found for this dataset, it will not be added to the new dataset : {}'.format(e))
    log.info('Added {} resources to the dataset'.format(resource_count))


def setup_dataset_dict(city_insee):
    # Base resources urls for the 9 dynamic datasets found in every town page in datagouv
    # These urls can't be retrieved via see API (see below) so we add them manually using the city insee number
    url_population = 'https://www.insee.fr/fr/statistiques/tableaux/2021173/COM/{}/popleg2013_cc_popleg.xls'
    url_figures = 'https://www.insee.fr/fr/statistiques/tableaux/2020310/COM/{}/rp2013_cc_fam.xls'
    url_education = 'https://www.insee.fr/fr/statistiques/tableaux/2020665/COM/{}/rp2013_cc_for.xls'
    url_employement = 'https://www.insee.fr/fr/statistiques/tableaux/2020907/COM/{}/rp2013_cc_act.xls'
    url_housing = 'https://www.insee.fr/fr/statistiques/tableaux/2020507/COM/{}/rp2013_cc_log.xls'
    url_sirene = 'http://212.47.238.202/geo_sirene/last/communes/{}.csv'
    url_zones = 'http://sig.ville.gouv.fr/Territoire/{}/onglet/DonneesLocales'
    url_budget = 'http://alize2.finances.gouv.fr/communes/eneuro/tableau.php?icom={}&dep=0{}&type=BPS&param=0'
    url_adresses = 'http://bano.openstreetmap.fr/BAN_odbl/communes/BAN_odbl_{}.csv'

    # Create a dataset_dict linking resources names with their url
    # Here we add manually the dynamic datasets
    dataset_dict = {'Population': url_population.format(city_insee),
                    'Chiffres cles': url_figures.format(city_insee),
                    'Diplomes - Formation': url_education.format(city_insee),
                    'Emploi': url_employement.format(city_insee),
                    'Logement': url_housing.format(city_insee),
                    'SIRENE': url_sirene.format(city_insee),
                    'Zonage des politiques de la ville': url_zones.format(city_insee),
                    'Comptes de la collectivite': url_budget.format(city_insee[2:], city_insee[:2]),
                    'Adresses': url_adresses.format(city_insee)}
    
    return dataset_dict


def get_name_from_siret(siret):

    apiKey = config.get('ckanext.ozwillo_organization_api.verifsiret_apikey', '')
    secretKey = config.get('ckanext.ozwillo_organization_api.verifsiret_secretkey', '')
    url = "https://www.numero-de-siret.com/api/siret?siret=" + siret
    result = None

    if apiKey == '' or secretKey == '':
        log.error('Verif-siret config incomplete, please register your api key and api secret in the config file')
        result = ''
        return result

    try:
        get = requests.get(url, auth=(apiKey, secretKey))
        if get.status_code != 200:
            raise requests.ConnectionError()
    except requests.exceptions.RequestException as err:
        log.error('An error occurred: {0}'.format(err))
    else:
        try:
            result = get.json()['array_return'][0]['LIBCOM']
        except (IndexError, TypeError, AttributeError):
            log.error('No organization found for this siret number')
    finally:
        return result
