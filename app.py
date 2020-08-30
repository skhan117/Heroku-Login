from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id='dX5sLVv7HCAv1hmrQKoF6T4ofQvIBYCX',
    client_secret='Jhi2wm4xDG7nM6VuGYVwkPdo6iX3DCtT0TFGKRIvyghB5WUsFEVDLlbeUfO0AWap',
    api_base_url='https://skhan117.us.auth0.com',
    access_token_url='https://skhan117.us.auth0.com/oauth/token',
    authorize_url='https://skhan117.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

@app.route('/')
def entry_point():
    # Root endpoint returns a simple message to verify the app's working.
    return 'Roooot, you got the root route up!'

# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
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
    return redirect('http://staticfeedenv.eba-8552m422.us-west-1.elasticbeanstalk.com/staticfeed') # was '/dashboard'

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='https://skhan117.us.auth0.com/login')

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)
  return decorated

@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': 'dX5sLVv7HCAv1hmrQKoF6T4ofQvIBYCX'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

# Make this different
if __name__ == "__main__":
    app.run(port=5005)
