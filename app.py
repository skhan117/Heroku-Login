# This is a generic login application that allows a user to login and log out of 
# other web applications. Authentication is handled by Auth0, and the application
# is setup for deployment to Heroku. All relevant endpoints must be enabled via
# the Auth0 console -- read Auth0's quickstart guide for relevant instructions. 

import os
from functools import wraps
import json

from werkzeug.exceptions import HTTPException
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

# Load environmental variables from a .env file in the root directory.
from os import environ as env
from dotenv import load_dotenv, find_dotenv
load_dotenv();

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")    # Generate a secret key as needed.

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=os.getenv("CLIENT_IDENTITY"),
    client_secret=os.getenv("CLIENT_SECRET"),
    api_base_url=os.getenv("API_BASE_URL"),
    access_token_url=os.getenv("ACCESS_TOKEN_URL"),
    authorize_url=os.getenv("AUTHORIZE_URL"),
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# Root endpoint returns a simple message to verify the app's started working.
@app.route('/')
def entry_point():
    return 'Roooot, you got the root route up!'

# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handle the response from the token endpoint.
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    # Redirect to the protected application's address.
    return redirect(os.getenv("REDIRECT_URL"))  

# The login route will allow the user to login.
@app.route('/login')
def login():
    # Redirect to this address after successful login.
    return auth0.authorize_redirect(redirect_uri=os.getenv("REDIRECT_URL") )

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)
  return decorated

# The dashboard route depicts the user's info if this feature is enabled via Auth0. 
@app.route('/dashboard')
@requires_auth
def dashboard():
    # Generate a userinfo dashboard.
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))

# Log out will clear session data and redirect to the address specified on the Auth0 application dashboard. 
@app.route('/logout')
def logout():
    # Clear session stored data.
    session.clear()
    # Redirect user to logout endpoint.
    params = {'returnTo': url_for('home', _external=True), 'client_id': os.getenv('CLIENT_IDENTITY')}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

# Make this different
if __name__ == "__main__":
    app.run(port=5005)