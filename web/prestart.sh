#! /usr/bin/env bash
# Don't do anything in this script, database is handled
# in setup_database as it's own dockerfile
# this script is called by the web setup

ls -lR /app

cat /app/data/config.ini

echo "Setting up DB"
python3.6 setup_database.py /app/data/database.db
echo "Finished setting up DB"

ls -lR /app

chmod 774 /app/data/database.db
chmod 774 /app/data

echo "done prestart"