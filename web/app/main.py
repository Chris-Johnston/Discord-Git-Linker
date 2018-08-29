# web client that handles receiving the authorization
# from GitHub, and logging it on a per-user basis

import requests
from flask import Flask, request, redirect
import sqlite3
import configparser
import datetime
import os

# use the working directory
config_file = 'data/config.ini'
database_file = 'data/database.db'

# read the config file and database file paths from environment variables
# these are set from the web Dockerfile

if 'WEB_CONFIG_FILE_PATH' in os.environ:
    config_file = os.environ.get('WEB_CONFIG_FILE_PATH')

if 'WEB_DATABASE_FILE_PATH' in os.environ:
    database_file = os.environ.get('WEB_DATABASE_FILE_PATH')

print(f'Config file: {config_file} Database file: {database_file}')

# read the config file contents
cfg = configparser.ConfigParser()
with open(config_file) as c:
    cfg.read_file(c)

# read the github configuration information from the config file
github_client_id = cfg['GitHub']['client_id']
github_client_secret = cfg['GitHub']['client_secret']

# establish a connection to the user auth db
user_auth_db = sqlite3.connect(database_file, check_same_thread=False)
cursor = user_auth_db.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cursor.fetchall())
cursor.close()


app = Flask(__name__)

def store_user_authorization_details(user_id: int, access_token: str):
    """
    Stores a discord User ID and GitHub access token in the
    UserGithubAuthorization table.
    :param user_id: The discord user ID.
    :param access_token: The user's GitHub access token.
    :return: None
    """
    c = user_auth_db.cursor()

    # insert into the table
    c.execute("""
    INSERT OR REPLACE INTO UserGithubAuthorization
     (DiscordUserId, GithubAuthorizationToken)
     VALUES
    (?, ?);""", (user_id, access_token))

    # commit the changes
    user_auth_db.commit()


def check_token(token: str) -> int:
    """
    Checks that a user login token is valid and not expired.
    Removes the token after it is checked, even if invalid.
    Returns the first DiscordUserId that is associated with that login token,
    if any.
    :param token:
    :return: The DiscordUserId that owns this token, or None if invalid.
    """
    c = user_auth_db.cursor()
    # Fetch the first DiscordUserId for the given token as long as it isn't expired.
    c.execute(
        '''
        SELECT DiscordUserId FROM UserLogin WHERE Token = ? AND Expiration >= ?;
        ''', (token, datetime.datetime.now()))
    result = c.fetchone()

    # delete all expired tokens, or all instances of this token
    c.execute('''DELETE FROM UserLogin WHERE Token = ? OR Expiration >= ?;''', (token, datetime.datetime.now()))
    # save changes to the database
    user_auth_db.commit()

    # The token was expired or didn't exist, so no user could be found in the table
    # just return None
    if result is None:
        return None
    # Return the user Id because it was found.
    return result[0]


@app.route('/')
def default():
    # TODO Make a nicer index page with an invite link for the bot.
    return "This is the test page, you shouldn't be here."


@app.route('/github/code')
def github_authorization_code():
    """
    GitHub OAuth Authorization Redirect Endpoint

    If the user accepts the request to authorize the application, GH will
    redirect back to this site with a code as a parameter.
    This code can be exchanged for an authorization token for a limited amount of time.

    The token parameter is the same as the token that we have previously generated,
    and authenticates that a request is for a specific Discord User ID.

    The state parameter is optional and not used.

    The request code is
    :return:
    """
    # Github auth code
    code = request.args.get('code')
    # Our login token
    token = request.args.get('token')

    # check that the token exists in the database and is still valid
    # invalid tokens will automatically be removed
    userid = check_token(token)

    if userid is None:
        # The supplied token was expired or invalid.
        return 'Invalid or expired login token. Please generate a new login token.', 403

    # exchange this code for an access token
    # populate a map with the required parameters
    params = {
        'client_id': github_client_id,
        'client_secret': github_client_secret,
        'code': code
    }
    # request json back from the API
    headers = {
        'Accept': 'application/json'
    }
    # send the request and wait for the response
    r = requests.post('https://github.com/login/oauth/access_token',
                  data=params, headers=headers)
    # OAuth access token successful
    if r.status_code == 200:
        # Parse the GH Access Token from the JSON response
        response = r.json()
        access_token = response['access_token']

        # Store the Discord User ID and the GH access token in the UserGithubAuthorization
        # table
        store_user_authorization_details(userid, access_token)
    else:
        return 501
        # Other status codes
        # return 'Encountered unexpected error when logging into Github OAuth.', 500

    # TODO: Render a template that will close the tab automatically after a few seconds.
    return 'User logged in successfully. You may now close this tab.', 200


@app.route('/github/login')
def github_login():
    """
    GitHub Service Login Endpoint

    Redirects the user to GitHub's Authorize Login page for this service.

    Requires the mandatory token parameter, which is a unique single-use string
    that is specific to a single Discord User ID.
    :return:
    """
    # Get the token from the request
    # This is a mandatory parameter.
    # This value is also not validated, you have to get redirected from Github
    # to have this parameter get validated.
    token = request.args.get('token')

    # Parameters for the redirect token
    params = {
        'token': token,
    }

    # Set up the redirect URL with the token
    r = requests.Request('GET', cfg['Login']['github_login_callback'], params=params).prepare().url

    # generate the oauth/authorize url
    request_parameters = {
        'client_id': github_client_id,
        # Scopes
        # repo needed for read access to code, commit statuses and private repos
        'scope': 'repo',
        # redirect url will contain token as a parameter
        'redirect_uri': r
    }
    # Make the redirect URL
    url = requests.Request('GET', 'https://github.com/login/oauth/authorize',
                           params=request_parameters).prepare().url

    # Redirect to this Github Login page
    return redirect(url, code=302)


if __name__ == '__main__':
    # To be used for debugging purposes
    app.run(host='0.0.0.0', port=5000)
