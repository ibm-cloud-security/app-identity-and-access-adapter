FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /bin/
COPY bin/appidentityandaccessadapter .
ENTRYPOINT [ "/bin/appidentityandaccessadapter" ]
CMD []
EXPOSE 47304