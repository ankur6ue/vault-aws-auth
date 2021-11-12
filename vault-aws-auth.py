from urllib import parse, request
import requests
from requests import ConnectionError, HTTPError
import botocore.session
import boto3
import base64
import json
import os
import configparser
from botocore.exceptions import ClientError


def read_policy(vault_server_addr: str, policy_name: str, token: str):
    url = vault_server_addr + '/v1/sys/policy/' + policy_name
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def create_policy(vault_server_addr: str, policy_name: str, token: str):
    url = vault_server_addr + '/v1/sys/policy/' + policy_name
    try:
        resp = requests.request('POST', url, headers={"X-Vault-Token": token}, data= \
            {"policy": 'path "kv/aws-auth-test/*" {capabilities = ["create", "read", "update", "delete", "list"]}'},
                                timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def read_role(vault_server_addr: str, vault_role: str, token: str):
    url = vault_server_addr + '/v1/auth/aws/role/' + vault_role
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError as e:
        print('We failed to reach a server.')
        return
    return resp


def create_role(vault_server_addr: str, vault_role: str, token: str, vault_policy: str, aws_iam_role: str):
    url = vault_server_addr + '/v1/auth/aws/role/' + vault_role
    try:
        resp = requests.request('POST', url, headers={"X-Vault-Token": token}, data= \
            {"auth_type": "iam",
             "policies": vault_policy,
             "max_ttl": "500h",
             "bound_iam_principal_arn": aws_iam_role}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def write_vault_secret(vault_server_addr, client_token, secret_path, secret):
    url = vault_server_addr + '/v1/kv/' + secret_path + '/config'
    try:
        resp = requests.request('POST', url, headers={"X-Vault-Token": client_token}, data=json.dumps(secret),
                                timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    return resp


def get_vault_secret(vault_server_addr, client_token, secret_path):
    # First get client authorization token

    url = vault_server_addr + '/v1/kv/' + secret_path + '/config'
    try:
        resp = requests.request('GET', url, headers={"X-Vault-Token": client_token}, timeout=1)
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError:
        print('We failed to reach a server.')
        return
    if resp.ok:
        return resp.json()


def headers_to_go_style(headers):
    retval = {}
    for k, v in headers.items():
        if isinstance(v, bytes):
            retval[k] = [str(v, 'utf-8')]
        else:
            retval[k] = [v]
    return retval


# This function will create a signed a GetCallerIdentity query using the AWS Signature v4 algorithm and
# return it back. The credentials used to sign the GetCallerIdentity request can come from a EC2 instance if this
# program is running on an EC2 instance - in which case the IAM Role attached to the EC2 instance must match
# the one used to create the vault role.
# In our case, we'll use an AWS user creds to get assume the IAM role and get temporary assume role credentials
def generate_vault_request(aws_access_key, aws_secret_key, aws_iam_role, awsIamServerId=None):
    # botocore.session.set_credentials()

    sts_client = boto3.client('sts', aws_access_key_id=aws_access_key,
                              aws_secret_access_key=aws_secret_key)

    try:
        print("attempting to obtain temporary STS creds")
        # These creds can be very short lived, they won't be needed after vault authenticates the caller identity
        assumed_role_object = sts_client.assume_role(
            RoleArn=aws_iam_role,
            RoleSessionName="S3AccessAssumeRoleSession",
            DurationSeconds=900  # Using the shortest DurationSeconds allowed by AWS
        )

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls
        credentials = assumed_role_object['Credentials']
    except ClientError as e:
        print("Failed to assume user provided IAM Role")
        print(e)
        return

    session = botocore.session.get_session()
    client = session.create_client('sts', aws_access_key_id=credentials['AccessKeyId'],
                                   aws_secret_access_key=credentials['SecretAccessKey'],
                                   aws_session_token=credentials['SessionToken'])
    endpoint = client._endpoint
    operation_model = client._service_model.operation_model('GetCallerIdentity')
    request_dict = client._convert_to_request_dict({}, operation_model)
    # X-Vault-AWS-IAM-Server-ID header can be used to mitigate against replay attacks -
    # eg., a signed GetCallerIdentity request stolen from a dev Vault instance and used to authenticate
    # to a prod Vault instance
    request_dict['headers']['X-Vault-AWS-IAM-Server-ID'] = awsIamServerId

    request = endpoint.create_request(request_dict, operation_model)

    return {
        'iam_http_request_method': request.method,
        'iam_request_url': str(base64.b64encode(bytes(request.url, 'utf-8')), 'utf-8'),
        'iam_request_body': str(base64.b64encode(bytes(request.body, 'utf-8')), 'utf-8'),
        'iam_request_headers': str(
            base64.b64encode(bytes(json.dumps(headers_to_go_style(dict(request.headers))), 'utf-8')), 'utf-8')
        # It's a CaseInsensitiveDict, which is not JSON-serializable
    }


# Here we'll pass the signed CallerIdentity query to vault, which will reconstruct the query and
# forwards it on to the AWS STS service. Depending on the response from the STS service, the vault server
# authenticates the client and return back a response containing a client_token, which can be used to perform
# further actions authorized by the policies attached to the vault role
def vault_iam_login(vault_server_addr, vault_role, params):
    url = vault_server_addr + '/v1/auth/aws/login'
    try:
        resp = requests.request('POST', url, data= \
            {
                "role": vault_role,
                "iam_http_request_method": "POST",
                "iam_request_url": params["iam_request_url"],
                "iam_request_body": params["iam_request_body"],
                "iam_request_headers": params['iam_request_headers']
            }, timeout=2)

    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        return
    except ConnectionError as e:
        print('We failed to reach a server.')
        return
    return resp


def run():
    # Read configuration
    config = configparser.ConfigParser()
    config.read('vault_settings.cfg')
    # Public IP address of the EC2 instance where vault is running
    vault_server_addr = config['DEFAULT']['VAULT_ADDR']
    # name of the vault policy that enables CRUD operations on SECRET_PATH
    vault_policy = config['DEFAULT']['VAULT_POLICY']
    # name of the vault role that will be associated with the AWS IAM Role and vault_policy
    vault_role = config['DEFAULT']['VAULT_ROLE']
    # vault root token required to create the vault policy and role
    vault_root_token = config['DEFAULT']['VAULT_ROOT_TOKEN']
    # The AWS IAM role attached to the vault role and used to establish user identity
    aws_iam_role = config['DEFAULT']['AWS_IAM_ROLE']
    # ACCESS/SECRET keys required to assume AWS IAM Role above
    aws_access_key = config['DEFAULT']['AWS_ACCESS_KEY']
    aws_secret_key = config['DEFAULT']['AWS_SECRET_KEY']
    # The path where secret will be written/read
    secret_path = config['DEFAULT']['SECRET_PATH']

    # Check to see if the vault policy required to perform operations at path kv/aws-auth-test/* already exists
    resp = read_policy(vault_server_addr, vault_policy, vault_root_token)
    # If not, let's create a policy
    if resp is None or resp.ok == False:
        resp = create_policy(vault_server_addr, vault_policy, vault_root_token)
        if resp and resp.ok:
            print("vault policy created successfully")

    if resp and resp.ok:
        # Try creating the role if it doesn't already exist
        # must first call vault auth enable aws on vault server
        # First check if role exists
        resp = read_role(vault_server_addr, vault_role, vault_root_token)
        if resp is None or resp.ok == False:
            # role doesn't exist, let's try to create it. We'll bind this role with the AWS IAM Role that will
            # serve as our identity and attach the policy created above to the role.
            resp = create_role(vault_server_addr, vault_role, vault_root_token, vault_policy, aws_iam_role)
            print("vault role created successfully")

    if resp is None or resp.ok == False:
        print("unable to read/create vault policy/role, exiting")
        exit(0)

    # We successfully created a vault policy and role, let's now create a signed GetCallerIdentity request
    params = generate_vault_request(aws_access_key, aws_secret_key, aws_iam_role, awsIamServerId=vault_server_addr)
    # Now let's pass this request to vault to authenticate. Upon successful authentication, vault will return back
    # a client_token that can be used to write/read secrets as allowed by the policy
    resp = vault_iam_login(vault_server_addr, vault_role, params)
    if resp and resp.ok:
        print("successfully login to vault using aws iam authorization")
        client_token = resp.json()['auth']['client_token']
        # write secret
        secret = {
            "data": {
                "foo": "bar",
                "zip": "zap"
            }
        }
        # Use the token to write a secret
        resp = write_vault_secret(vault_server_addr, client_token, secret_path, secret)
        if resp.ok:
            # read secret back
            resp = get_vault_secret(vault_server_addr, client_token, secret_path)
            if resp:
                # compare retrieved secret with master copy
                retrieved_secret = resp["data"]
                if retrieved_secret == secret:
                    print("retrieved secret matches master copy")


if __name__ == '__main__':
    run()
