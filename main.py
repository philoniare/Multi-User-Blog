#!/usr/bin/env python
from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

# ------------------------------------------------------------------------
#                             Base Handler 
# ------------------------------------------------------------------------
class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """ Helper for accessing the auth instance as a property """
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """
      Helper for accessing a subset of the user attributes in session
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """ Helper for accessing the current logged in user """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """ Returns the implementation of the user model"""    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Helper for accessing the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """ Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)
      try:
          webapp2.RequestHandler.dispatch(self)
      finally:
          self.session_store.save_sessions(self.response)

# ------------------------------------------------------------------------
#                             Auth & Session 
# ------------------------------------------------------------------------
class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    password = self.request.get('password')

    unique_properties = ['user_name']
    user_data = self.user_model.create_user(user_name,
      unique_properties=['username'], username=user_name,
      password_raw=password, verified=True)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Username already exists')
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    msg = 'Successfully signed up'

    self.display_message(msg)

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('authenticated.html')

# ------------------------------------------------------------------------
#                            Article Handlers
# ------------------------------------------------------------------------

class MainHandler(BaseHandler):
  def get(self):
    self.render_template('home.html')


config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['username']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'Secret_KEY'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated')
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
