import urllib
from functools import wraps

import requests
from apiflask import HTTPTokenAuth
from flask import current_app, jsonify, request, session
from jose import JWTError, jwt

import kutils

auth = HTTPTokenAuth(
    scheme="Bearer",
    header="Authorization",
    security_scheme_name="BearerAuth",
    description="An OAuth2 token issued by the STELAR IDP by using endpoint or GUI issuance.",
)

security_doc = "BearerAuth"


def api_verify_token(token):
    """
    Verify JWT tokens issued by Keycloak for POST requests that require authentication.

    Args:
        token: A JWT token issued by Keycloak after user authentication.

    Returns:
        A boolean: True if the token is valid; False otherwise.
    """

    config = current_app.config["settings"]

    token = urllib.parse.unquote(token).strip()
    # config = current_app.config['keycloak_settings']
    keycloak_issuer = config["KEYCLOAK_ISSUER_URL"]
    keycloak_client_id = [
        "master-realm",
        "account",
    ]  # Client ID registered in Keycloak(check the aud for different users)
    keycloak_jwks_url = (
        config["KEYCLOAK_URL"]
        + "/realms/"
        + config["REALM_NAME"]
        + "/protocol/openid-connect/certs"
    )

    try:
        # Fetch JWKS (public keys) from Keycloak
        jwks_response = requests.get(keycloak_jwks_url)
        jwks = jwks_response.json()

        # Extract token header to identify the correct public key
        unverified_header = jwt.get_unverified_header(token)

        # Find the public key matching the 'kid' in the token header
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
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
                        algorithms=["RS256"],
                        audience=audience,  # Verify against each audience
                        issuer=keycloak_issuer,
                    )
                    # If one audience works, return True
                    return True
                except JWTError:
                    # If JWTError occurs, try the next audience
                    continue

    except Exception as e:
        return False

    # If no valid key is found, return False
    return False


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if request.headers.get("Authorization"):
                # Extract the token from the 'Authorization' header
                access_token = request.headers.get("Authorization").split(" ")[1]
            else:
                # Try to extract token from session if not provided.
                access_token = session.get("access_token")
                if access_token is None:
                    response = {
                        "success": False,
                        "help": request.url,
                        "error": {
                            "__type": "Authentication Error",
                            "name": "Bearer Token is not Valid",
                        },
                    }
                    return response, 401

            # Check if the token is valid and corresponds to an admin user
            if not kutils.introspect_admin_token(access_token):
                response = {
                    "success": False,
                    "help": request.url,
                    "error": {
                        "__type": "Authorization Error",
                        "name": "Bearer Token is not related to an admin user",
                    },
                }
                return response, 403

        except (IndexError, ValueError):
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": "Authorization Bearer Token is missing or malformed",
                },
            }
            return response, 401
        except Exception as e:
            response = {
                "success": False,
                "help": request.url,
                "error": {"__type": "Unexpected Error", "name": str(e)},
            }
            return response, 500

        return f(*args, **kwargs)

    return decorated_function


def token_active(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if request.headers.get("Authorization"):
                # Extract the token from the 'Authorization' header
                access_token = request.headers.get("Authorization").split(" ")[1]
            else:
                # Try to extract token from session if not provided.
                access_token = session.get("access_token")
                if access_token is None:
                    response = {
                        "success": False,
                        "help": request.url,
                        "error": {
                            "__type": "Authentication Error",
                            "name": "Bearer Token is not Valid",
                        },
                    }
                    return response, 401

            # Verify the token keys.
            if not api_verify_token(access_token):
                response = {
                    "success": False,
                    "help": request.url,
                    "error": {
                        "__type": "Authentication Error",
                        "name": "Bearer Token could not be verified",
                    },
                }
                return response, 401

            # Check if the token is valid
            if not kutils.introspect_token(access_token):
                response = {
                    "success": False,
                    "help": request.url,
                    "error": {
                        "__type": "Authorization Error",
                        "name": "Bearer Token is expired",
                    },
                }
                return response, 403

        except (IndexError, ValueError):
            response = {
                "success": False,
                "help": request.url,
                "error": {
                    "__type": "Authorization Error",
                    "name": "Authorization Bearer Token is missing or malformed",
                },
            }
            return response, 400
        except Exception as e:
            response = {
                "success": False,
                "help": request.url,
                "error": {"__type": "Unexpected Error", "name": str(e)},
            }
            return response, 500

        return f(*args, **kwargs)

    return decorated_function
