FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /bin/
COPY bin/ibmcloudappid .
ENTRYPOINT [ "/bin/ibmcloudappid" ]
CMD []
EXPOSE 47304