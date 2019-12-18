FROM python:3.5-alpine
ADD . /code
WORKDIR /code
# this RUN is used for resolving issues between alpine and pyOpenSSL
RUN set -e; \
  apk update \
  && apk add --virtual .build-deps gcc python3-dev musl-dev libffi-dev \
  # TODO workaround start
  && apk del libressl-dev \
  && apk add openssl-dev \
  && pip install cryptography==2.2.2 \  
  && apk del openssl-dev \
  && apk add libressl-dev \
  # TODO workaround end
  && apk add postgresql-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-deps
RUN pip install -r requirements.txt
CMD ["python","-u", "client1.py"]
