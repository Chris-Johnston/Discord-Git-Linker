"""
Sets up all the tables of the SQLite database file.
Because this is just SQLite, dropping tables is as easy as:
`rm database.db`

Accepts the path to the database file as the first argument.
"""

import sys
import sqlite3

if __name__ == '__main__':

    # get path as first arg value
    db_path = sys.argv[1]

    # establish a connection to the db
    database = sqlite3.connect(db_path, check_same_thread=False)

    # create tables if they don't already exist
    c = database.cursor()

    # discord user ID to github auth token table
    c.execute("""CREATE TABLE IF NOT EXISTS userauth
                            (id INT PRIMARY KEY,
                            discordUserID TEXT,
                            githubAuthorizationToken TEXT);""")

    # temporary login link table
    # this stores single use tokens that are sent as a DM to users
    # which are used to log a user into this service
    c.execute('''
                CREATE TABLE IF NOT EXISTS
                login
                (
                loginId INT PRIMARY KEY,
                discordUserID UNSIGNED BIG INT,
                token TEXT,
                expiration DATETIME
                )''')

    # channel link table
    # links a channel and guild id to a repo in the format user/repoName
    c.execute('''
        CREATE TABLE IF NOT EXISTS link_channels
        ( guildId UNSIGNED BIG INT,
          channelId UNSIGNED BIG INT,
          authorUserId UNSIGNED BIG INT,
          createdAt DATETIME,
          repoUrl TEXT
          )''')

    # links a guild to a repo in the format user/repoName
    # the authorOnly flag allows for this behavior to only work for the user who
    # made the link, effectively enabling a per-user link
    c.execute('''
            CREATE TABLE IF NOT EXISTS link_guilds
            ( guildId UNSIGNED BIG INT,
              authorUserId UNSIGNED BIG INT,
              createdAt DATETIME,
              repoUrl TEXT,
              authorOnly INT
              )''')

    # close cursor when done
    c.close()
    # commit changes to the db
    database.commit()
