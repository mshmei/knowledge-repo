import logging
import os
import uuid
from ..proxies import db_session, current_repo, current_user
from ..models import User

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Blueprint,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from flask_bootstrap import Bootstrap
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import requests



metadata_url_for = {
    # EXAMPLE APPLICATION
    # 'test': 'http://idp.oktadev.com/metadata',
    # 'example-okta-com': 'https://periscopedata.okta.com/app/exk5vj2xj6KdQ6LDZ1t7/sso/saml/metadata',
    'example-okta-com': 'https://periscopedata.okta.com/app/periscopedata_pdknowledgerepo_1/exk5z0615lJbBDd6K1t7/sso/saml/metadata'
    }

# Create blueprint for routing saml auth
blueprint = Blueprint('saml_auth', __name__,
                      template_folder = '../templates', static_folder='../static')

def saml_client_for(idp_name=None):
    '''
    This takes the idp and returns a set of configurations used by saml2.config.config
    '''
    # This formats the settings from the xml response given by the idp for Saml2Config.load()
    # Using our example above, we can render the our external urls using
    # saml_client_for('example-okta-com')
    if idp_name not in metadata_url_for:
        raise Exception("Settings for IDP '{}' not found".format(idp_name))
    acs_url = url_for(
        "saml_auth.idp_initiated",
        idp_name=idp_name,
        _external=True)
    https_acs_url = url_for(
        "saml_auth.idp_initiated",
        idp_name=idp_name,
        _external=True,
        _scheme='https')
    
    #   SAML metadata changes very rarely. On a production system,
    #   this data should be cached as approprate for your production system.
    rv = requests.get(metadata_url_for[idp_name])

    settings = {
        'metadata': {
            'inline': [rv.text]
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
                        (https_acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests, since signed requests only make
                # sense in a situation where you control both the SP and IdP
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }  
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


# Creating routing for the main saml auth login page
@blueprint.route("/saml-auth/login")
def saml_auth_page():
    return render_template('saml-login-form.html', idp_dict=metadata_url_for)

# This renders the feed used for the redirect by the idp response
@blueprint.route('/feed', methods=['GET'])
def render_feed():
    return render_template("index-feed.html")


# Creatubg the SP initiated flow
@blueprint.route("/saml/login/<idp_name>")
def sp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    reqid, info = saml_client.prepare_for_authenticate()
    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key is 'Location':
            redirect_url = value
    response = redirect(redirect_url, code=302)
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


# Create routing for initiating the SAML auth from the SP
@blueprint.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text
    session['saml_attributes'] = authn_response.ava
    email = authn_response.ava['Email'][0]
    name = authn_response.ava['FirstName'][0] + ' ' + authn_response.ava['LastName'][0]
    user = User.query.filter_by(identifier=email).first()
    if not user:
       user = User(identifier = email)
       user.name = name
       user.email = email
       db_session.add(user)
       db_session.commit()

    user.authenticated = True
    login_user(user)
    url = url_for('saml_auth.render_feed')
    # NOTE:
    #   On a production system, the RelayState MUST be checked
    #   to make sure it doesn't contain dangerous URLs!
    # The following below will go ahead and set url = None since
    # ('RelayState', u'')
    # if 'RelayState' in request.form:
    #     url = request.form['RelayState']
    return redirect(url)

@blueprint.route("/saml-auth/logout")
def saml_auth_logout():
    user = current_user
    logout_user()
    url = url_for('saml_auth.saml_auth_page')
    return redirect(url)
