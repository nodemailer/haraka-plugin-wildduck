FROM node:lts-alpine as builder

RUN apk add --no-cache git python3 py3-pip make g++

WORKDIR /app

RUN git clone https://github.com/haraka/Haraka.git ./ --branch master
RUN npm install --production
RUN npm install haraka-plugin-wildduck


FROM node:lts-alpine as app

ENV NODE_ENV production

RUN apk add --no-cache tini
RUN apk add --no-cache openssl

WORKDIR /app
COPY --from=builder /app /app

ENTRYPOINT ["/sbin/tini", "--", "node", "haraka.js"]
