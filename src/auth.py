from apiflask import HTTPTokenAuth
from flask import current_app, session
import logging
import urllib
from jose import jwt, JWTError
from requests.models import Response
import logging
import requests
import utils


logging.basicConfig(level=logging.DEBUG)

auth = HTTPTokenAuth(scheme='Bearer', header='Authorization')

security_doc = ["ApiKeyAuth"]

@auth.verify_token
def api_verify_token(token):
    """
    Verify JWT tokens issued by Keycloak for POST requests that require authentication.
    
    Args:
        token: A JWT token issued by Keycloak after user authentication.
        
    Returns:
        A boolean: True if the token is valid; False otherwise.
    """

    config = current_app.config['settings']

    # Try to see if there is a token in the session field if not one was explicitely provided
    if token is None or token.strip() == "":
        token = session.get('access_token')
        if token is None:
            return False

    # logging.debug("Starting token verification")
    token = urllib.parse.unquote(token).strip()
    # config = current_app.config['keycloak_settings']
    keycloak_issuer = "https://"+config['KEYCLOAK_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']+"/realms/"+config['REALM_NAME']  # Issuer URL from Keycloak
    keycloak_client_id = 'master-realm'  # Client ID registered in Keycloak(check the aud for different users)
    keycloak_jwks_url = config['KEYCLOAK_URL']+"/realms/"+config['REALM_NAME']+"/protocol/openid-connect/certs"


    try:
        # logging.debug(f"Token received: {token}")
        # Get the JWKS (public keys) from Keycloak to verify JWT tokens
        jwks_response = requests.get(keycloak_jwks_url)
        jwks = jwks_response.json()

        # logging.debug(f"JWKS response: {jwks}")

        # Extract token header to identify the correct public key (kid)
        unverified_header = jwt.get_unverified_header(token)
        # logging.debug(f"Unverified header: {unverified_header}")

        # Find the public key matching the 'kid' in the token header
        # rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = utils.construct_rsa_public_key(key['n'], key['e'])
                #logging.debug(f"Found RSA key: {rsa_key}")
                # rsa_key = {
                #     'kty': key['kty'],
                #     'kid': key['kid'],
                #     'use': key['use'],
                #     'n': key['n'],
                #     'e': key['e']
                # }

        # If we found the correct key, verify the token
        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=['RS256'],
                audience=keycloak_client_id,  # Ensure the audience matches the client ID
                issuer=keycloak_issuer        # Ensure the token is from the right Keycloak issuer
            )
            #logging.debug(f"Token payload: {payload}")
            
            # If token verification succeeds, authentication is valid
            return True
        
    except JWTError as e:
        # Token is invalid
        print(f"JWTError: {e}")
        #logging.error(f"JWTError: {e}")
        # return "Invalid Token", 401
        return False
    except Exception as e:
        # Other errors (e.g., network issue, token parsing error)
        print(f"Error: {e}")
        #logging.error(f"General error: {e}")
        return False

    # If no valid key is found, return False
    return False    