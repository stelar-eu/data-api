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

    #logging.debug("Starting token verification")
    token = urllib.parse.unquote(token).strip()
    # config = current_app.config['keycloak_settings']
    keycloak_issuer = "https://"+config['KEYCLOAK_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']+"/realms/"+config['REALM_NAME']  # Issuer URL from Keycloak
    keycloak_client_id = ['master-realm','account']  # Client ID registered in Keycloak(check the aud for different users)
    keycloak_jwks_url = config['KEYCLOAK_URL']+"/realms/"+config['REALM_NAME']+"/protocol/openid-connect/certs"


    try:
        # Fetch JWKS (public keys) from Keycloak
        jwks_response = requests.get(keycloak_jwks_url)
        jwks = jwks_response.json()

        # Extract token header to identify the correct public key
        unverified_header = jwt.get_unverified_header(token)

        # Find the public key matching the 'kid' in the token header
        rsa_key = None
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                break
        
        # If we found the correct RSA key
        if rsa_key:
            for audience in keycloak_client_id:
                try:
                    # Try verifying the token with each audience in the list
                    payload = jwt.decode(
                        token,
                        rsa_key,
                        algorithms=['RS256'],
                        audience=audience,  # Verify against each audience
                        issuer=keycloak_issuer
                    )
                    # If one audience works, return True
                    return True
                except JWTError:
                    # If JWTError occurs, try the next audience
                    continue

    except Exception as e:
        # Log other exceptions such as network issues
        logging.error(f"Error during token verification: {e}")
        return False

    # If no valid key is found, return False
    return False    