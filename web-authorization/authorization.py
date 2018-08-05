# web client that handles receiving the authorization
# from GitHub, and logging it on a per-user basis

import requests
from flask import Flask, request, redirect, abort
import github
import sqlite3
import configparser
import sys
import secrets
import datetime

# use the working directory
config_file = 'config.ini'
database_file = 'githublinker.db'

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
github_client_id = cfg['GitHub']['client_id']
github_client_secret = cfg['GitHub']['client_secret']

# discord oauth config
discord_client_id = cfg['Discord']['client_id']
discord_client_secret = cfg['Discord']['client_secret']

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
            (id INT PRIMARY KEY,
            discordUserID TEXT,
            githubAuthorizationToken TEXT);""")
    user_auth_db.commit()


def store_user_authorization_details(user_id, access_token):
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
    INSERT OR REPLACE INTO userAuth
     (discordUserID, githubAuthorizationToken)
     VALUES
    (?, ?);""", (user_id, access_token))

    # commit the changes
    user_auth_db.commit()


# def get_user_for_access_token(access_token: str):
#     """
#     Hits the GitHub api to get the user for a given access token
#     :param access_token:
#     :return:
#     """
#     # log into github with the given access_token
#     gh = github.Github(login_or_token=access_token,
#                        client_id=github_client_id,
#                        client_secret=github_client_secret)
#
#     # get the current user
#     current_user = gh.get_user()
#
#     return current_user

@app.route('/discord/code')
def discord_authorization_code():

    code = request.args.get('code')

    print('discord/code')
    return ':ok_hand:'

def check_token(token: str) -> int:
    """
    Checks that a token is valid and not expired
    removes the token after checking it
    :param token:
    :return:
    """
    print('checking token', token)
    c = user_auth_db.cursor()

    c.execute(
        '''
        SELECT userId FROM login WHERE token = ? AND expiration >= ?;
        ''', (token, datetime.datetime.now()))
    result = c.fetchone()
    print('result', result)

    print('removing the token from the database')

    # delete all expired tokens, or all instances of this token
    c.execute('''DELETE FROM login WHERE token = ? OR expiration >= ?;''', (token, datetime.datetime.now()))
    user_auth_db.commit()

    print('deleted from db')

    if result is None:
        return None
    # return the user id
    return result[0]

@app.route('/github/code')
def github_authorization_code():
    """
    under the github oauth web flow docs

    if the user accepts your request, GH redirects back
    to your site witha temporary code paramter
    as well as the state provided in the previous state parameter
    :return:
    """
    code = request.args.get('code')

    token = request.args.get('token')

    print('got the token', token)

    # check that the token exists in the database and is still valid
    userid = check_token(token)

    if userid is None:
        # print('url expired or invalid')
        # return abort(400)
        return ('url expired or invalid', 403)
    print('user id', userid)

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
        # user = get_user_for_access_token(access_token)

        # store the matching user id and access token in our
        # credentials db
        store_user_authorization_details(userid, access_token)

        print('userid', userid, 'token', access_token)
    else:
        return 'something broke'

    return 'OK, you can close this window now'


@app.route('/github/login')
def github_login():
    # get the token
    token = request.args.get('token')

    print('logging in with the token', token)

    params = {
        'token': token,
    }

    # set up the github redirect url with the token
    r = requests.Request('GET', cfg['GitHub']['redirect_uri'], params=params).prepare().url

    print('redirect url will be', r)

    # generate the oauth/authorize url
    request_parameters = {
        'client_id': github_client_id,
        'scope': 'repo read:user repo:status repo_deployment',
        'redirect_uri': r
    }

    req = requests.Request('GET', 'https://github.com/login/oauth/authorize',
                           params=request_parameters)
    url = req.prepare().url
    print('url', url)

    # redirect to the github authorization page for the bot
    return redirect(url, code=302)

# use this only for testing
if __name__ == '__main__':
    app.config['TESTING'] = True
    app.run(debug=True)
