FROM python:3.7
LABEL maintainer="chjohnston@protonmail.com"

RUN mkdir /app /app/data /app/setup /app/bot /app/web

WORKDIR /app/setup

COPY . /app/setup
COPY ./config.ini /app/data/config.ini

# Run the database init script to create the database file under /app/data/database.db
CMD ["python", "./setup_database.py", "/app/data/database.db"]

RUN ls -lR /app