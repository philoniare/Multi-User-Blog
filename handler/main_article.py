from .base import Handler
from google.appengine.ext import db

class ArticleHandler(Handler):
	def get(self, article_id):
		article_key = db.Key.from_path('Article', int(article_id))
		article = db.get(article_key)
		if not article:
			self.error(404)
			self.response.out.write('Article with the given id was not found.')
			return
		self.render("article", article=article)