FROM python:3.7-stretch
LABEL maintainer="chjohnston@protonmail.com"

# set working dir to app
WORKDIR /app/bot

# copy everything to the /app directory
COPY . /app/bot

# install prereqs
RUN python -m pip install -r requirements.txt --trusted-host pypi.python.org

# RUN python bot.py config.ini database.db
CMD ["python", "bot.py", "/app/data/config.ini", "/app/data/database.db"]