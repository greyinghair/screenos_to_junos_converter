FROM python:3.12-alpine
ARG APP_BRANCH=unknown
ENV APP_BRANCH=${APP_BRANCH}
# WORKDIR ../app
COPY ../requirements.txt requirements.txt
RUN apk add --no-cache "zlib>=1.3.2-r0" git \
    && python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]