#!/usr/bin/python
#
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
module: github_organization

short_description: Create/Rename a GitHub organization.
description:
    - Create or Rename a GitHub organization.

version_added: "2.5"

options:
  state:
    description:
      -  The desired state for the repository
    choices: ['present', 'archive', 'absent']
    default: 'present'

  name:
    description:
      - The name of the repository
    required: True

  owner:
    description:
      - The owner of the repository that is being created, either a user or an
        organization. If not specified, then the token_user is used as the owner.

  base_url:
    description:
      - The base URL for the GitHub Enterprise instance being connected to.
        The URL can either be the URL to the web interface (upon which the /api/v3 path will be appended)
        or full URL to the API endpoint.
        e.g. https://github.domain.com or https://github.domain.com/api/v3
    required: True

  token:
    description:
      - The access token for the I(token_user)
    required: True

  token_user:
    description:
      - The username of the user for the I(token).
        The user must have the necessary privileges to be able to create repositories
        in the GitHub Enterprise organization if owner is specifed.
    required: True

  validate_certs:
    description:
      - Whether or not to validate the certificate returned from the GitHub Enterprise
        instance. This is useful when using a self signed certificate.
    type: bool
    default: True

  private:
    description:
      - Whether or not the repository is private.
    type: bool
    default: False

  has_issues:
    description:
      - Flag to enable issues on the repository.
    type: bool
    default: True

  has_projects:
    description:
      - Flag to enable projects on the repository.
    type: bool
    default: True

  has_wiki:
    description:
      - Flag to enable wiki on the repository.
    type: bool
    default: True

  gitignore_template:
    description:
      - The name of the gitignore template to apply to the repository.
        The names are any that the GitHub instance has defined, e.g. 'Haskell'
    default: None
    required: False

  allow_pr_squash_merge:
    description:
      - Allow squash merging of Pull Requests.
    type: bool
    default: True

  allow_pr_merge_commit:
    description:
      - Allow merging of Pull Request with merge commits.
    type: bool
    default: True

  allow_pr_squash_merge:
    description:
      - Allow rebase merging of Pull Requests.
    type: bool
    default: True

  create_inital_commit:
    description:
      - Create the repository with an initial commmit with an empty README.
    type: bool
    default: False

author:
  - "Peter Murray (@peter-murray)"
'''

RETURN = '''
# name:
#   description: The name of the organization
#   returned: always
#   type: string
#   sample: my-organization
# id:
#   description: The id of the organization inside GitHub Enterprise
#   returned: always
#   type: int
#   sample: 1
# created_at:
#   description: The timestamp of when the organization was created
#   returned: always
#   type: str
#   sample: '2017-06-25T12:20:25Z'
# updated_at:
#   description: The timestamp of the last update to the organization
#   returned: always
#   type: str
#   sample: '2017-06-25T12:20:25Z'
# collaborators:
#   description: The number of collaborators in the organization
#   returned: always
#   type: int
#   sample: 10
# public_repo_count:
#   description: The count of public repositories in the organization
#   returned: always
#   type: int
#   sample: 0
# private_repo_count:
#   description: The count of private repositories in the organization
#   returned: always
#   type: int
#   sample: 1
# default_repo_permission:
#   description: The default permission for repositories in the organization
#   returned: always
#   type: string
#   sample: read
'''

EXAMPLES = '''
- name: Create an Organization
  github_organization:
    state: present
    base_url: https://github-enterprise.domain.com
    token: 'xxxxxxxxxxxxxxxxxxxxxxxxxxx'
    token_user: token-username
    name: my-repository
    owner: an-organization

'''

import base64
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.basic import AnsibleModule

CREATE_ONLY_PARAMETERS = ['gitignore_template', 'auto_init', 'license_template']

PULL_REQUEST_PARAMETERS = ['allow_merge_commit', 'allow_rebase_merge', 'allow_squash_merge']

def _build_api_url(base_url, path):
    url = base_url

    if url.endswith('/'):
        if path.startswith('/'):
            url += path[1:]
        else:
            url += path
    else:
        if path.startswith('/'):
            url += path
        else:
            url += '/' + path

    return url


def _get_auth_header(user, token):
    auth = base64.encodestring(('%s:%s' % (user, token)).encode()).decode().replace('\n', '')
    return 'Basic %s' % auth


def _get_base_url(module):
    url = module.params['base_url']

    if not url.endswith('api/v3'):
        url = _build_api_url(url, 'api/v3')

    return url


def _generate_repository_result(repo):
    return {
        'name': repo['name'],
        'full_name': repo['full_name'],
        'description': repo['description'],
        'private': repo['private'],
        'url': repo['html_url'],
        'default_branch': repo['default_branch'],
        'has_issues': repo['has_issues'],
        'has_wiki': repo['has_wiki'],
        'has_pages': repo['has_pages'],
        'archived': repo['archived'],
        'created_at': repo['created_at'],
        'updated_at': repo['updated_at'],
        'pull_requests': {
            'allow_rebase_merge': repo['allow_rebase_merge'],
            'allow_squash_merge': repo['allow_squash_merge'],
            'allow_merge_commit': repo['allow_merge_commit']
        },
        'organization': repo['organization']['login']
    }


def _get_repository(module, base_url, auth_header, owner, repo_name):
    url = _build_api_url(base_url, 'repos/{0}/{1}'.format(owner, repo_name))
    headers = _build_request_headers(auth_header)

    r, info = fetch_url(module,
                        url,
                        method='GET',
                        headers=headers)
    if info['status'] == 200:
        return module.from_json(r.read())#TODO
    else:
        return None


def _get_repository_owner(module):
    owner = module.params['owner']
    if owner is None:
        owner = module.params['token_user']
    return owner


def _is_organization_repository(module):
    return module.params['owner'] is not None


def _build_request_headers(auth_header):
    return {'Authorization': auth_header}


def _parse_error_response(module, body):
    try:
        failure = module.from_json(body)
        error_message = failure['message']
    except ValueError:
        error_message = body

    return error_message


def _create_repository(module, base_url , auth_header, owner, repo_name):
    result = {'changed': False}
    headers = _build_request_headers(auth_header)

    if _is_organization_repository(module):
        url = _build_api_url(base_url, 'orgs/{0}/repos'.format(owner))
    else:
        url = _build_api_url(base_url, 'user/repos')

    data = {
        'name': repo_name
        , 'private': module.params['private']
        , 'description': module.params['description']
        , 'has_issues': module.params['has_issues']
        , 'has_projects': module.params['has_projects']
        , 'has_wiki': module.params['has_wiki']
        #, 'team_id': organization_team_id
        , 'auto_init': module.params['auto_init']
    }
    _update_pr_settings(data, module)

    for k in ['license_template', 'gitignore_template']:
        if module.params[k] is not None:
            data[k] = module.params[k]

    r, info = fetch_url(module,
                        url,
                        method='POST',
                        data=module.jsonify(data),
                        headers=headers)
    if info['status'] == 201:
        repo = _get_repository(module, base_url, auth_header, owner, repo_name)
        result['changed'] = True
        result.update(_generate_repository_result(repo))
    else:
        error_message = _parse_error_response(module, info['body'])
        module.fail_json(msg='Failed to create repository: {0}'.format(error_message))

    return result


def _update_data(data, module, existing_repo, key, parameter=None):
    if parameter is None:
        value = module.params[key]
    else:
        value = module.params[parameter]

    existing_value = existing_repo[key]

    if existing_value != value:
        data.update({key: value})


def _update_pr_settings(data, module, existing_repo=None):
    pull_request_settings = module.params['pull_requests']

    if pull_request_settings:
        for k in PULL_REQUEST_PARAMETERS:
            value = pull_request_settings.get(k, True)

            if existing_repo:
                if existing_repo[k] != value:
                    data.update({k: value})
            else:
                data.update({k: value})


def _update_repository(module, base_url, auth_header, existing_repo):
    owner = existing_repo['owner']['login']
    repo_name = existing_repo['name']

    # data = {'name': repo_name} #TODO we do not allow renaming here, but it might be possible in the API, need to check that
    data = {} #TODO we do not allow renaming here, but it might be possible in the API, need to check that
    _update_data(data, module, existing_repo, 'private')
    _update_data(data, module, existing_repo, 'has_issues')
    _update_data(data, module, existing_repo, 'has_projects')
    _update_data(data, module, existing_repo, 'has_wiki')
    _update_data(data, module, existing_repo, 'default_branch')
    _update_pr_settings(data, module, existing_repo)

    if len(data) > 0: #TODO if you can rename, this condition may not hold
        result = _update_repository_request(module, base_url, auth_header, owner, repo_name, data)
    else:
        result = {'changed': False}
        result.update(_generate_repository_result(existing_repo))

    return result


def _update_repository_request(module, base_url, auth_header, owner, repo_name, data):
    result = {'changed': False}

    payload = {'name': repo_name}
    payload.update(data)

    url = _build_api_url(base_url, 'repos/{0}/{1}'.format(owner, repo_name))
    headers = _build_request_headers(auth_header)

    r, info = fetch_url(module,
                        url,
                        method='PATCH',
                        data=module.jsonify(payload),
                        headers=headers)
    if info['status'] == 200:
        repo = _get_repository(module, base_url, auth_header, owner, repo_name)
        result.update({'changed': True})
        result.update(_generate_repository_result(repo))
    else:
        error_message = _parse_error_response(module, info['body'])
        module.fail_json(msg='Failed to update repository: {0}'.format(error_message))

    return result


def archive_repository(module, auth_header):
    result = {'changed': False}

    repository_name = module.params['name']
    owner = _get_repository_owner(module)
    base_url = _get_base_url(module)

    existing_repository = _get_repository(module, base_url, auth_header, owner, repository_name)

    if existing_repository is not None:
        if not existing_repository['archived']:
            data = {'archived': True}
            result = _update_repository_request(module, base_url, auth_header, owner, repository_name, data)
    else:
        module.fail_json(msg='Repository {0}/{1} was not found'.format(owner, repository_name))

    return result


def _contains_update_only_parameters(module):
    return module.params['default_branch'] != 'master'


def _contains_create_only_parameters(module):
    return (module.params['gitignore_template'] is not None
        or module.params['license_template'] is not None
        or module.params['auto_init'])


def create_or_update_repository(module, auth_header):
    result = {'changed': False}

    repository_name = module.params['name']
    owner = _get_repository_owner(module)
    base_url = _get_base_url(module)

    existing_repository = _get_repository(module, base_url, auth_header, owner, repository_name)

    if existing_repository is None:
        result = _create_repository(module, base_url, auth_header, owner, repository_name)

        if _contains_update_only_parameters(module):
            result = _update_repository(module, base_url, auth_header, existing_repository)
            # Ensure that even if update does not change anything, we report as changed
            result['changed'] = True
    else:
        if _contains_create_only_parameters(module) and module.params['strict']:
            module.fail_json('Parameters contain values that are only valid at creation time!')
        result = _update_repository(module, base_url, auth_header, existing_repository)

    return result


def delete_repository(module, auth_header):
    result = {'changed': False}

    repo_name = module.params['name']
    owner = _get_repository_owner(module)
    base_url = _get_base_url(module)

    existing_repository = _get_repository(module, base_url, auth_header, owner, repo_name)

    if existing_repository:
        url = _build_api_url(base_url, 'repos/{0}/{1}'.format(owner, repo_name))
        headers = _build_request_headers(auth_header)

        r, info = fetch_url(module,
                            url,
                            method='DELETE',
                            headers=headers)
        if info['status'] == 204:
            result.update({'changed': True})
        else:
            error_message = _parse_error_response(module, info['body'])
            module.fail_json(msg='Failed to delete repository: {0}'.format(error_message))

    return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            owner=dict(required=False),
            base_url=dict(required=True),
            token=dict(no_log=True, required=True),
            token_user=dict(required=True),
            validate_certs=dict(type='bool', default=True),
            state=dict(choices=['present', 'archive', 'absent'], default='present'),
            private=dict(type='bool', default=False),
            has_issues=dict(type='bool', default=True),
            has_projects=dict(type='bool', default=True),
            has_wiki=dict(type='bool', default=True),
            gitignore_template=dict(required=False),
            pull_requests=dict(type='dict'),
            # create_initial_commit=dict(type='bool', default=False),
            description=dict(required=False),
            default_branch=dict(default='master'),
            auto_init=dict(type='bool', default=False),
            license_template=dict(),
            strict=dict(type='bool', default=False)
        ),
        supports_check_mode=False,
    )

    user = module.params['token_user']
    token = module.params['token']
    state = module.params['state']
    auth_header = _get_auth_header(user, token)

    if state == 'present':
        result = create_or_update_repository(module, auth_header)
    elif state == 'archive':
        result = archive_repository(module, auth_header)
    elif state == 'absent':
        result = delete_repository(module, auth_header)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
