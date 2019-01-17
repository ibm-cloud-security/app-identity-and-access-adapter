# appid-mixer-adapter-plugin

Prototype of App ID integration with Istio.

## Run

### Start Istio Mixer and Adapter

#### App ID Mixer Adapter

```
export ISTIO=$GOPATH/src/istio.io                                                        ✹
export MIXER_REPO=$GOPATH/src/istio.io/istio/mixer
cd $MIXER_REPO/adapter/ibmcloudappid
go build . && go run cmd/main.go 47304
```

#### Mixer

```
export ISTIO=$GOPATH/src/istio.io 

$GOPATH/out/darwin_amd64/release/mixs server \                                                 ⏎ ✭
    --configStoreURL=fs://$GOPATH/src/istio.io/istio/mixer/adapter/ibmcloudappid/testdata \
    --log_output_level=attributes:debug
```

### Send direct request to mixer

```
pushd $ISTIO/istio && make mixc && $GOPATH/out/darwin_amd64/release/mixc report -s destination.service="svc.cluster.local" -i request.size=1

$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:abc"

$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer token"

$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTcifQ.eyJpc3MiOiJhcHBpZC1vYXV0aC5zdGFnZTEuZXUtZ2IuYmx1ZW1peC5uZXQiLCJleHAiOjE1NDc2MTA2MzEsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTQ3NjA3MDMxLCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.NjhoELlVfHHMhxHw9EIrPqvfct2Ns9j4cg4f2wjtL5efDl48WLRyp-LgeBDVfajK0LANlxeBvooXxBn7dNhjc2cm0Rnx-lYpj3JYpYiMfFSiUg8WjDrMyvWBU4v61GlQlNQWUERxAmMzsnQijz57V6emuyZ2mNIZWjx6QzCjgCarQ_9U5HmoJOZ2eTAovHCiwjtgDDeEa3_9DkKvYC3Ekfr-UwAUxfkSydQQ2hBO8cf1SuReXaTIMYs21NWZJSBPH4k-w6azLOR_qzkvkHeS1rW-7_MKISgW06FISPAOIUFZ_NJlaYcAJe9cepno3IHmUtBkro28h08WBUzGGSuXJw"


$GOPATH/out/darwin_amd64/release/mixc check -s destination.service="svc.cluster.local" --stringmap_attributes "request.headers=authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC0wNTdmNDQxOS03MzYzLTQ0ZDktYWNiNy0xNzA3MjQ4ZWU1ZTQtMjAxOC0wOC0wMlQxMjowMzo1Ny42MTQifQ.eyJpc3MiOiJhcHBpZC1vYXV0aC5zdGFnZTEuZXUtZ2IuYmx1ZW1peC5uZXQiLCJleHAiOjE1NDc1OTY0NjksImF1ZCI6IjlhMDJiZGZkLTFmYWItNGFlZi1hOTE3LTQ4YjJiNWQxMzFjZiIsInN1YiI6IjlhMDJiZGZkLTFmYWItNGFlZi1hOTE3LTQ4YjJiNWQxMzFjZiIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTQ3NTkyODY5LCJ0ZW5hbnQiOiIwNTdmNDQxOS03MzYzLTQ0ZDktYWNiNy0xNzA3MjQ4ZWU1ZTQiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.TJ-AFySbaosodACcJUJtH-cPDyBRcjg6FPv7u4R_M_OR0aq_oOYTqBI86QFliZNIizT3VPAFhRRUjSbgfH9zH3GvhIotC4pj4re9zx8HnbWXsPbplmwi7VlO8MlzUGH3EXijkk5-2Fs-GUOVhBhCre6Hm2ofx5CgP9aZzdDfLW9TB0cFupk1FfsbTI9hfW-7IjQrT2bEKCtNuTPT-ndLAwrHRB1PhG3gKPKojdcFIxdpBxvaG5pDIJJnEkNj-yyNnEH7PGfIqVRQAotSoFEOIQBXk7Q24qVbz5TYiiB2tVdy1GjPBbEs11B9JfEg6vzU_amgshiIdJCF67deJotl8A"
```