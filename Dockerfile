#FROM golang:1.11 as builder
##WORKDIR /go/src/istio.io/
#WORKDIR .
#COPY ./ .
#RUN pwd
#RUN ls -la
#RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -v -o executable cmd/main.go

FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /bin/
#COPY --from=builder /go/src/github.com/username/myootadapter/bin/mygrpcadapter .
COPY executable .
#ENV APPID_URL=https://appid-multi-cloud-manager.anton-dev.us-south.containers.mybluemix.net/api
#ENV APPID_APIKEY=DefaultAppidApiKey
#ENV CLUSTER_NAME=DefaultClusterName
#ENV CLUSTER_GUID=DefaultClusterGuid
#ENV CLUSTER_LOCATION=DefaultClusterLocation
ENTRYPOINT [ "/bin/executable" ]
CMD [ "47304" ]
EXPOSE 47304