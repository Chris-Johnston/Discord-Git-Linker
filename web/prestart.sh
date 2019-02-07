#! /usr/bin/env bash

ls -lR /app

cat /app/data/config.ini

echo "Setting up DB"
python3.6 setup_database.py /app/data/database.db
echo "Finished setting up DB"

ls -lR /app
chmod 777 -R /app/data

echo "done prestart"