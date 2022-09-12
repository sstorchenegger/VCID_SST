# pull official base image
FROM python:3.9.5-slim-buster

# set work directory
WORKDIR /usr/src/app

# copy project
COPY . .

# install system dependencies
RUN apt-get update && apt-get install -y netcat

# install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt


# run entrypoint.sh
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]