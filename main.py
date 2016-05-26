#!/usr/bin/env python
from google.appengine.ext import db
import webapp2
# import entities
import model.article
import model.user

from handler.base import Handler

# Article Handlers
from handler.create_article import CreateArticleHandler
from handler.main_article import ArticleHandler

# User Handlers

class MainHandler(Handler):
    def get(self):
    	articles = db.GqlQuery("SELECT * from Article ORDER BY created DESC")
    	for article in articles:
    		print(article.title)
        self.render("articles", articles=articles)

app = webapp2.WSGIApplication([
    (r'/', MainHandler),
	(r'/articles/create', CreateArticleHandler),
	(r'/articles/(\d+)', ArticleHandler)
], debug=True)
