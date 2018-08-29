FROM tiangolo/uwsgi-nginx-flask:python3.6
LABEL maintainer="chjohnston@protonmail.com"

RUN mkdir /app/data /app/bot /app/web

# set working dir to app
WORKDIR /app

# copy everything to the /app directory
COPY . /app
COPY ./app /app
COPY config.ini /app/data/config.ini

# install prereqs
RUN python -m pip install -r /app/requirements.txt --trusted-host pypi.python.org

# set the environment variables for the config file path and the database path
ENV WEB_CONFIG_FILE_PATH /app/data/config.ini
ENV WEB_DATABASE_FILE_PATH /app/data/database.db

EXPOSE 5000
EXPOSE 80

# Let the uwsgi-nginx-flask app run