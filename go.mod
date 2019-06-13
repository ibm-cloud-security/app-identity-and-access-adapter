module github.com/ibm-cloud-security/policy-enforcer-mixer-adapter

go 1.12

require (
	github.com/PuerkitoBio/goquery v1.5.0
	github.com/dgrijalva/jwt-go/v4 v4.0.0-20190410170817-8222805572f2
	github.com/evanphx/json-patch v4.2.0+incompatible // indirect
	github.com/gogo/googleapis v1.2.0
	github.com/gogo/protobuf v1.2.1
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef
	github.com/golang/protobuf v1.3.1 // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/json-iterator/go v1.1.6 // indirect
	github.com/prometheus/common v0.2.0
	github.com/spf13/cobra v0.0.3
	github.com/stretchr/testify v1.3.0
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f // indirect
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/grpc v1.20.1
	gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce
	istio.io/api v0.0.0-20190515205759-982e5c3888c6
	istio.io/istio v0.0.0-20190516081059-beb17827e164
	k8s.io/api v0.0.0-20190612125737-db0771252981
	k8s.io/apimachinery v0.0.0-20190612125636-6a5db36e93ad
	k8s.io/client-go v10.0.0+incompatible
	k8s.io/code-generator v0.0.0-20190612125529-c522cb6c26aa
	k8s.io/utils v0.0.0-20190506122338-8fab8cb257d5 // indirect
)

replace (
	golang.org/x/sync => golang.org/x/sync v0.0.0-20181108010431-42b317875d0f
	golang.org/x/sys => golang.org/x/sys v0.0.0-20190209173611-3b5209105503
	golang.org/x/tools => golang.org/x/tools v0.0.0-20190313210603-aa82965741a9
	k8s.io/api => k8s.io/api v0.0.0-20190612125737-db0771252981
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190612125636-6a5db36e93ad
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190612125919-5c45477a8ae7
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190612125529-c522cb6c26aa
	k8s.io/component-base => k8s.io/component-base v0.0.0-20190612130303-4062e14deebe
)
