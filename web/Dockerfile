FROM python:3.8-slim
#RUN mkdir /app
#ADD . /app
WORKDIR /usr/src/app2
COPY requirement.txt ./
RUN pip install --upgrade pip \
  && pip install --no-cache-dir -r requirement.txt
COPY . .
RUN pip install ./en_core_web_sm-2.0.0.tar.gz
CMD ["python", "compare.py"]