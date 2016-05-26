from .base import Handler
class CreateArticleHandler(Handler):
	def get(self):
		self.render("create")
	
	def post(self):
		title = self.request.get('title')
		text = self.request.get('text')
		if title and text:
			article = Article(title=title, text=text)
			article.put()
		else:
			self.render("create")