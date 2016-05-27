### Multi-User Blog (Medium Clone)
Blog made with Google App Engine Python as the back-end, using Jinja templating engine and Materialize. 
Implemented secure authentication and session management with webapp2.
Credit for https://blog.abahgat.com/2013/01/07/user-authentication-with-webapp2-on-google-app-engine/
for a comprehensive tutorial on the subject matter.

### Functionality
- User management with registration, login and signout
- Logged in users can create/edit/delete blog posts, comments and like blog posts
- Makes use of secure hashed cookies to store the session with timestamped tokens 

### To run locally:
- Install GoogleAppEngine
- Add existing application by pointing the Path to the project directory
- And click Run to start the app
- Go to localhost:<port> to access the application