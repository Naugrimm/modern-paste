import flask
from flask import request
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user as login
from flask_login import logout_user as logout

import constants.api
import database.user
from api.decorators import require_form_args
from modern_paste import app
from uri.authentication import *
from util.exception import *
import config
import ldap
from pprint import pprint


def get_ldap_connection():
  conn = ldap.initialize(config.LDAP_PROVIDER_URL)
  return conn


def try_ldap_auth(username, password):
  conn = get_ldap_connection()
  conn.simple_bind_s(
      username + config.LDAP_ACCOUNT_SUFFIX,
      password
  )
  user_list = conn.search_st(
      config.LDAP_SEARCH_BASE,
      ldap.SCOPE_SUBTREE,
      config.LDAP_USER_FILTER % (username),
      None,
      0,
      -1
  )

  try:
    ldap_user = user_list.pop()[1]
    ldap_user_mail = ldap_user["mail"].pop()
    ldap_user_display_name = ldap_user["displayName"].pop()
  except Exception:
    raise ldap.INVALID_CREDENTIALS

  try:
    database.user.get_user_by_username(ldap_user_mail)
  except UserDoesNotExistException:
    # the user does not exist - try to create it
    new_user = database.user.create_new_user(
        username=ldap_user_mail,
        password=password,
        signup_ip=flask.request.remote_addr,
        name=ldap_user_display_name,
        email=ldap_user_mail,
    )
  return ldap_user_mail


@app.route(LoginUserURI.path, methods=['POST'])
@require_form_args(['username', 'password'])
def login_user():
  """
  Authenticate and log in a user.
  """
  data = request.get_json()
  success_resp = flask.jsonify({
      constants.api.RESULT: constants.api.RESULT_SUCCESS,
      constants.api.MESSAGE: None,
      'username': data['username'],
  }), constants.api.SUCCESS_CODE

  if current_user.is_authenticated:
    # Already logged in; no action is required
    return success_resp

  if config.ENABLE_LDAP_AUTH:
    try:
      user_email = try_ldap_auth(data['username'], data['password'])
      data['username'] = user_email
    except ldap.INVALID_CREDENTIALS:
      return flask.jsonify(constants.api.AUTH_FAILURE), constants.api.AUTH_FAILURE_CODE
  else:
    try:
      if not database.user.authenticate_user(data['username'], data['password']):
        return flask.jsonify(constants.api.AUTH_FAILURE), constants.api.AUTH_FAILURE_CODE
    except UserDoesNotExistException:
      return flask.jsonify(constants.api.NONEXISTENT_USER_FAILURE), constants.api.NONEXISTENT_USER_FAILURE_CODE

  login(
      user=database.user.get_user_by_username(data['username']),
      remember=bool(data.get('remember_me', False)),
  )
  return success_resp


@app.route(LogoutUserURI.path, methods=['POST'])
@login_required
def logout_user():
  """
  Log the current user out, as applicable.
  """
  username = str(current_user.username)
  logout()
  return flask.jsonify({
      constants.api.RESULT: constants.api.RESULT_SUCCESS,
      constants.api.MESSAGE: None,
      'username': username,
  }), constants.api.SUCCESS_CODE


@app.route(AuthStatusURI.path, methods=['POST'])
def auth_status():
  """
  Gets the authentication status for the current user, if any.
  """
  return flask.jsonify({
      'is_authenticated': bool(current_user.is_authenticated),
      'user_details': {
          'username': getattr(current_user, 'username', None),
          'user_id': getattr(current_user, 'user_id', None),
      },
  }), constants.api.SUCCESS_CODE
