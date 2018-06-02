# web client that handles receiving the authorization
# from GitHub, and logging it on a per-user basis

import requests
from flask import Flask, request
import github
import sqlite3
import configparser
import sys

# use the working directory
config_file = 'config.ini'
database_file = 'userauth.db'

# if len(sys.argv) > 1:
#     # first parameter points towards the general config file
#     config_file = sys.argv[0]
#     # the second parameter points towards the database
#     database_file = sys.argv[1]

print(f'using the config file: {config_file}')

# read the config file contents
cfg = configparser.ConfigParser()
with open(config_file) as c:
    cfg.read_file(c)

# github app stuff
client_id = cfg['GitHub']['client_id']
client_secret = cfg['GitHub']['client_secret']

# establish a connection to the user auth db
user_auth_db = sqlite3.connect(database_file, check_same_thread=False)

app = Flask(__name__)


def setup_user_auth_tables():
    """
    Creates the user auth table in the database if it doesn't already
    exist
    :return:
    """
    c = user_auth_db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS userauth
            (github_user_id TEXT PRIMARY KEY,
            github_user_login TEXT,
            authorization_token TEXT)""")
    user_auth_db.commit()


def store_user_authorization_details(user_id, user_login_name, access_token):
    """
    store details about the user's authentication in the server
    while we really don't need to include both the user id and the
    user login name, I think that it might help when debugging
    :param user_id:
    :param user_login_name:
    :param access_token:
    :return:
    """
    # ensure that the authorization tables are set up already
    setup_user_auth_tables()

    c = user_auth_db.cursor()

    # insert into the table
    c.execute("""
    INSERT OR REPLACE INTO userAuth VALUES
    (?, ?, ?);""", (user_id, user_login_name, access_token))

    # commit the changes
    user_auth_db.commit()


def get_user_for_access_token(access_token: str):
    """
    Hits the GitHub api to get the user for a given access token
    :param access_token:
    :return:
    """
    # log into github with the given access_token
    gh = github.Github(login_or_token=access_token,
                       client_id=client_id,
                       client_secret=client_secret)

    # get the current user
    current_user = gh.get_user()

    return current_user

@app.route('/code')
def code():
    """
    under the github oauth web flow docs

    if the user accepts your request, GH redirects back
    to your site witha temporary code paramter
    as well as the state provided in the previous state parameter
    :return:
    """
    code = request.args.get('code')

    # exchange this code for an access token

    # populate a map with the required parameters
    params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code
    }
    # request json back from the API
    headers = {
        'Accept': 'application/json'
    }

    # send the request, I don't really care about blocking
    # this endpoint right now
    r = requests.post('https://github.com/login/oauth/access_token',
                  data=params, headers=headers)
    # if we got a good status code, then we are good
    if r.status_code == 200:
        # parse out the access token from the response
        response = r.json()
        access_token = response['access_token']

        # login with this token and fetch the user id
        user = get_user_for_access_token(access_token)

        # store the matching user id and access token in our
        # credentials db
        store_user_authorization_details(user.id, user.login, access_token)

    return 'OK'

# use this only for testing
if __name__ == '__main__':
    app.run()
