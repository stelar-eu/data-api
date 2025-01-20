from flask import current_app


def get_demo_ckan_token():
    """Generate an API token for an existing user in CKAN. Requires authentication of the user in CKAN to generate a token.

    Args:
        data: A JSON with user identifier (or name) and the name to be given to the new token.

    Returns:
        A JSON with the response to this request, containing the generated API token.
    """
    config = current_app.config["settings"]

    # EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/user/token/create -d '{"user": "test_user5", "name": "test5_API_token"}'
    stelarapi_token = config.get("CKAN_ADMIN_TOKEN", "No CKAN token provided to ENV")

    return stelarapi_token

    # package_headers, resource_headers = utils.create_CKAN_headers(stelarapi_token)

    # data = '{"user":"ckan_admin","name":"demoStelarToken"}'

    # if data:
    #     token_metadata = json.loads(data)

    # # Make a POST request to the CKAN API with the parameters
    # response = requests.post("https://"+config['MAIN_INGRESS_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']+"/dc/api/3/action/"+'api_token_create', json=token_metadata, headers=package_headers, verify=False)  #auth=HTTPBasicAuth(config.username, config.password))

    # if response.json()['success']:
    #     return response.json()['result']['token']
