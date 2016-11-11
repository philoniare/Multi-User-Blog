#!/usr/bin/env python
from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2
import jinja2

from webapp2_extras import auth
from webapp2_extras import sessions
from models import Article
from models import Comment
from models import DummyEntity


from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

# ------------------------------------------------------------------------
#                             Config & Decorators
# ------------------------------------------------------------------------
template_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
                 autoescape=True)

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

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)
  
  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
  
  def render_template(self, template, **kw):
    user = self.user_info
    self.write(self.render_str(template, user=user, **kw))

  def display_message(self, message):
    """ Utility function to display a template with a simple message."""
    self.render_template('message.html', message=message)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
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

  def _serve_page(self, login_status=False):
    username = self.request.get('username')
    self.render_template('login.html', username=username, login_status=login_status)

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
class ArticleHandler(BaseHandler):
  def get(self, article_key):
    user_id = self.user_info['user_id']
    article = ndb.Key(urlsafe=article_key).get()
    comments = Comment.query_comments(article.key).fetch(10)
    self.render_template('article.html', article=article, 
      comments=comments, user_id=str(user_id))

class ArticleEditHandler(BaseHandler):
  @user_required
  def get(self, article_key):
    article = ndb.Key(urlsafe=article_key).get()
    user_id = self.user_info['user_id']
    user_key = ndb.Key('User', user_id)
    if article.user_key == user_key:
      self.render_template('edit_article.html', article=article)
    else:
      msg = "Sorry, you can't edit another user's articles."
      self.display_message(msg)
  def post(self, article_key):
    title = self.request.get('title')
    content = self.request.get('content')
    article_key = article_key
    article = ndb.Key(urlsafe=article_key).get()
    article.title = title
    article.content = content
    article.put()
    self.redirect(self.uri_for('home'))

class ArticleDeleteHandler(BaseHandler):
  @user_required
  def get(self, article_key):
    article = ndb.Key(urlsafe=article_key).get()
    user_id = self.user_info['user_id']
    user_key = ndb.Key('User', user_id)
    if article.user_key == user_key:
      article.key.delete()
      self.redirect(self.uri_for('my_articles'))
    else:
      msg = "Sorry, you can't delete another user's articles."
      self.display_message(msg)
    
class ArticleCreateHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('create_article.html')
  
  def post(self):
    title = self.request.get('title')
    content = self.request.get('content')
    user_id = self.user_info['user_id']
    user_key = ndb.Key('User', user_id)
    article = Article(title=title, likes=[],
      user_key=user_key, content=content)
    article.put()
    self.redirect(self.uri_for('my_articles'))

class ArticleLikeHandler(BaseHandler):
  @user_required
  def get(self, article_key):
    article = ndb.Key(urlsafe=article_key).get()
    user_id = self.user_info['user_id']
    user_key = ndb.Key('User', user_id)
    if user_key in article.likes:
      # Checks if user has already liked the article
      msg = "You have already liked this article"
      self.display_message(msg)
    elif article.user_key == user_key:
      # Checks if the article's author is the current user
      msg = "Sorry, you can't like your own article"
      self.display_message(msg)
    else:
      logging.info(article.likes)
      article.likes.append(user_key)
      article.put()
      self.redirect(self.uri_for('home'))

class ArticleUserHandler(BaseHandler):
  @user_required
  def get(self):
    user_id = self.user_info['user_id']
    user_key = ndb.Key('User', user_id)
    articles = Article.query(Article.user_key == user_key).fetch()
    self.render_template('user_articles.html', articles=articles)

# ------------------------------------------------------------------------
#                            Comment Handlers
# ------------------------------------------------------------------------
class CommentCreateHandler(BaseHandler):
  @user_required
  def post(self, article_key):
    article = ndb.Key(urlsafe=article_key).get()
    text = self.request.get('text')
    comment = Comment(text=text, parent=article.key, 
      username = self.user_info['username'],
      user_id=str(self.user_info['user_id']))
    comment.put()
    self.redirect(self.uri_for('home'))

class CommentEditHandler(BaseHandler):
  @user_required
  def post(self, comment_key):
    comment = ndb.Key(urlsafe=comment_key).get()
    text = self.request.get('text')
    comment.text = text
    comment.put()
    self.redirect(self.uri_for('home'))

class CommentDeleteHandler(BaseHandler):
  @user_required
  def get(self, comment_key):
    comment = ndb.Key(urlsafe=comment_key).get()
    comment.key.delete()
    self.redirect(self.uri_for('home'))

class MainHandler(BaseHandler):
  def get(self, articles=None):
    articles = Article.query()
    self.render_template('home.html', articles=articles)

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
    webapp2.Route('/my/articles', ArticleUserHandler, name='my_articles'),
    webapp2.Route(r'/article/create', ArticleCreateHandler, name='create_article'),
    webapp2.Route(r'/article/like/<article_key:.+>', ArticleLikeHandler),
    webapp2.Route(r'/article/edit/<article_key:.+>', ArticleEditHandler),
    webapp2.Route(r'/article/delete/<article_key:.+>', ArticleDeleteHandler),
    webapp2.Route(r'/article/<article_key:.+>', ArticleHandler),
    webapp2.Route(r'/comment/create/<article_key:.+>', CommentCreateHandler, name='create_comment'),
    webapp2.Route(r'/comment/edit/<comment_key:.+>', CommentEditHandler),
    webapp2.Route(r'/comment/delete/<comment_key:.+>', CommentDeleteHandler),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
