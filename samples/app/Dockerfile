FROM node:8
WORKDIR "/app"
ADD . /app
RUN npm install
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
EXPOSE 8000
CMD ["npm", "start"]
