"""
Sets up all the tables of the SQLite database file.
Because this is just SQLite, dropping tables is as easy as:
`rm database.db`

Accepts the path to the database file as the first argument.
"""

import sys
import sqlite3


def setup(path: str):
    # get path as first arg value
    db_path = path

    print(f'Database Path: {path}')

    # establish a connection to the db
    database = sqlite3.connect(db_path, check_same_thread=False)

    # create tables if they don't already exist
    c = database.cursor()

    # discord user ID to github auth token table
    c.execute('''
        CREATE TABLE IF NOT EXISTS UserGithubAuthorization
            (UserAuthorizationId INT PRIMARY KEY,
             DiscordUserId TEXT,
             GithubAuthorizationToken TEXT);''')

    # temporary login link table
    # this stores single use tokens that are sent as a DM to users
    # which are used to log a user into this service
    c.execute('''
        CREATE TABLE IF NOT EXISTS UserLogin
        (UserLoginId INT PRIMARY KEY,
         DiscordUserId UNSIGNED BIG INT,
         Token TEXT,
         Expiration DATETIME);''')

    # channel link table
    # links a channel and guild id to a repo in the format user/repoName
    c.execute('''
        CREATE TABLE IF NOT EXISTS LinkChannels
        (GuildId UNSIGNED BIG INT,
         ChannelId UNSIGNED BIG INT,
         AuthorDiscordUserId UNSIGNED BIG INT,
         CreatedAt DATETIME,
         RepoName TEXT);''')

    # links a guild to a repo in the format user/repoName
    # the authorOnly flag allows for this behavior to only work for the user who
    # made the link, effectively enabling a per-user link
    c.execute('''
        CREATE TABLE IF NOT EXISTS LinkGuilds
        (GuildId UNSIGNED BIG INT,
         AuthorDiscordUserId UNSIGNED BIG INT,
         CreatedAt DATETIME,
         RepoName TEXT,
         AuthorOnly INT);''')

    # commit changes to the db
    database.commit()
    # close cursor when done
    c.close()

    # open up the cursor again
    # and list all of the tables
    cursor = database.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    print(cursor.fetchall())
    cursor.close()

if __name__ == '__main__':
    print('Setting up the database.')
    setup(sys.argv[1])
    print('Done setting up database.')
