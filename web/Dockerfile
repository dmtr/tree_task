FROM python:3.5.1
RUN mkdir -p /app/tree_task
ADD tree_task /app/tree_task/
RUN pip install --upgrade pip
WORKDIR /app
RUN pip3 install -r tree_task/requirements.txt
