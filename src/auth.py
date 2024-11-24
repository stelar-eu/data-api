from apiflask import HTTPTokenAuth
from flask import current_app, session, jsonify, request
import logging
import urllib
from jose import jwt, JWTError
import logging
import requests
from functools import wraps
import kutils


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


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:

            # Extract the token from the 'Authorization' header
            access_token = request.headers.get('Authorization').split(" ")[1]
            
            # Check if the token is valid and corresponds to an admin user
            if not kutils.introspect_admin_token(access_token):
                response = {
                    'success': False,
                    'help': request.url,
                    'error': {
                        '__type': 'Authorization Error',
                        'name': 'Bearer Token is not related to an admin user'
                    }
                }
                return response, 403
        except (IndexError, ValueError):
            response = {
                'success': False,
                'help': request.url,
                'error': {
                    '__type': 'Authorization Error',
                    'name': 'Authorization Bearer Token is missing or malformed'
                }
            }
            return response, 400
        except Exception as e:
            response = {
                'success': False,
                'help': request.url,
                'error': {
                    '__type': 'Unexpected Error',
                    'name': str(e)
                }
            }
            return response, 500
        
        return f(*args, **kwargs)
    
    return decorated_function


def token_active(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:

            if request.headers.get('Authorization'):
                # Extract the token from the 'Authorization' header
                access_token = request.headers.get('Authorization').split(" ")[1]
            else:
                raise ValueError
            
            # Check if the token is valid and corresponds to an admin user
            if not kutils.introspect_token(access_token):
                response = {
                    'success': False,
                    'help': request.url,
                    'error': {
                        '__type': 'Authorization Error',
                        'name': 'Bearer Token is expired'
                    }
                }
                return response, 403
            
        except (IndexError, ValueError):
            response = {
                'success': False,
                'help': request.url,
                'error': {
                    '__type': 'Authorization Error',
                    'name': 'Authorization Bearer Token is missing or malformed'
                }
            }
            return response, 400
        except Exception as e:
            response = {
                'success': False,
                'help': request.url,
                'error': {
                    '__type': 'Unexpected Error',
                    'name': str(e)
                }
            }
            return response, 500
        
        return f(*args, **kwargs)
    
    
    return decorated_function