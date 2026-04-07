FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi \
    && apk add --no-cache git

COPY . .

CMD ["python", "convert.py"]
