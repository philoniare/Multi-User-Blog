import time
import webapp2_extras.appengine.auth.models

from google.appengine.ext import ndb

from webapp2_extras import security

class User(webapp2_extras.appengine.auth.models.User):
  def set_password(self, raw_password):
    """ Sets the password for the current user
    
        :param raw_password:
            The raw password which will be hashed and stored
    """
    self.password = security.generate_password_hash(raw_password, length=12)

  @classmethod
  def get_by_auth_token(cls, user_id, token, subject='auth'):
    """ Returns a user object based on a user ID and token.

        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
    """
    token_key = cls.token_model.get_key(user_id, subject, token)
    user_key = ndb.Key(cls, user_id)
    # Use get_multi() to save a RPC call.
    valid_token, user = ndb.get_multi([token_key, user_key])
    if valid_token and user:
        timestamp = int(time.mktime(valid_token.created.timetuple()))
        return user, timestamp

    return None, None

class Article(ndb.Model):
    """ Model for Individual Articles with User parent """
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    date = ndb.DateTimeProperty(auto_now_add = True)
    user_key = ndb.KeyProperty(required = True)
    likes = ndb.KeyProperty(kind="User", repeated = True)

    @classmethod
    def query_articles(cls, ancestor_key):
        return cls.query(ancestor=ancestor_key).order(-cls.date)

class Comment(ndb.Model):
    """ 
        Model for individual comments on articles.
        Has both Articles and Users as Ancestors
    """
    user_id = ndb.StringProperty(required = True)
    username = ndb.StringProperty(required = True)
    text = ndb.StringProperty(required = True)
    date = ndb.DateTimeProperty(auto_now_add = True)

    @classmethod
    def query_comments(cls, ancestor_key):
        return cls.query(ancestor=ancestor_key).order(-cls.date)

class DummyEntity(ndb.Model):
    """ Dummy Entity for syncing query statements after updates """
    date = ndb.DateTimeProperty(auto_now_add = True)