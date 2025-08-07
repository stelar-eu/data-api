import random
import smtplib
import ssl
from flask import current_app, session, url_for

"""
This module handles email sending functionalities for the STELAR KLMS application.
It includes sending OTP emails for email verification and sending verification emails with a link.
Methods used from this module should be called within a Flask application context.
It uses SMTP settings from the Flask app's configuration and handles errors related to email sending.
It also includes basic email validation using the `email_validator` library.
"""


def send_otp_email(to_email):
    """
    Sends the OTP to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config["settings"]  # Fetch SMTP settings from app config

    smtp_server = config["SMTP_SERVER"]
    smtp_port = config["SMTP_PORT"]
    sender_email = config["SMTP_EMAIL"]
    sender_password = config["SMTP_PASSWORD"]

    # Generate the OTP
    otp = random.randint(100000, 999999)

    # Email subject and sender name
    subject = "Verify Your New Email Address"
    sender_name = "STELAR KLMS"

    # Ensure USER_NAME exists in session
    user_name = session.get("USER_USERNAME", "User")

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {user_name},

Your OTP to verify your email change is: {otp}.

If you did not request this change, please contact our support team and consider changing your password.

If you received this email by accident, please ignore it.

Kind Regards,
STELAR KLMS
"""
    # Create the full email message with subject, sender, and receiver
    full_message = f"Subject: {subject}\nFrom: {sender_name} <{sender_email}>\nTo: {to_email}\n\n{plain_message}"

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(smtp_server, int(smtp_port), context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, full_message)
        return otp

    except Exception as e:
        # Log the error
        raise Exception(f"Error sending OTP email: {str(e)}")


def send_verification_email(to_email, vftoken, id, fullname):
    """
    Sends the email verification to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config["settings"]  # Fetch SMTP settings from app config

    smtp_server = config["SMTP_SERVER"]
    smtp_port = config["SMTP_PORT"]
    sender_email = config["SMTP_EMAIL"]
    sender_password = config["SMTP_PASSWORD"]

    # Email subject and sender name
    subject = "Verify Your Email Address"
    sender_name = "STELAR KLMS"

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {fullname},

Follow this link to verify your email: 

{config['MAIN_EXT_URL']}{url_for('dashboard_blueprint.verify_email')}?id={id}&vftoken={vftoken}

If you received this email by accident, please ignore it.

Kind Regards,
STELAR KLMS
"""
    # Create the full email message with subject, sender, and receiver
    full_message = f"Subject: {subject}\nFrom: {sender_name} <{sender_email}>\nTo: {to_email}\n\n{plain_message}"

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(smtp_server, int(smtp_port), context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, full_message)
    except Exception as e:
        # Log the error
        raise Exception(f"Error sending verification email: {str(e)}")
