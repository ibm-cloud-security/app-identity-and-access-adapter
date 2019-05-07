// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// THIS FILE IS AUTOMATICALLY GENERATED.

package authnz

import (
	"context"

	"istio.io/istio/mixer/pkg/adapter"
)

// Template authnZ defines an authorization and authentication adapter template

// Fully qualified name of the template
const TemplateName = "authnz"

// Instance is constructed by Mixer for the 'authnz' template.
//
// The `authorization` template defines parameters for performing policy
// enforcement within Istio. It is primarily concerned with enabling Mixer
// adapters to make decisions about who is allowed to do what.
// In this template, the "who" is defined in a Subject message. The "what" is
// defined in an Action message. During a Mixer Check call, these values
// will be populated based on configuration from request attributes and
// passed to individual authorization adapters to adjudicate.
type Instance struct {
	// Name of the instance as specified in configuration.
	Name string

	// A subject contains a list of attributes that identify
	// the caller identity.
	Subject *Subject

	// An action defines "how a resource is accessed".
	Action *Action
}

// Output struct is returned by the attribute producing adapters that handle this template.
//
// OutputTemplate defines OAuth 2.0 cookies to apply to response headers
// These are primarily used in OAuth 2.0 / OIDC web strategy
// flows and will be remain empty during most flows.
type Output struct {
	fieldsSet map[string]bool

	// The access token cookie using in OAuth 2.0 flows
	AccessTokenCookie string

	// The ID token cookie using in OAuth 2.0 flows
	IdTokenCookie string

	// The refresh token cookie using in OAuth 2.0 flows
	RefreshTokenCookie string
}

func NewOutput() *Output {
	return &Output{fieldsSet: make(map[string]bool)}
}

func (o *Output) SetAccessTokenCookie(val string) {
	o.fieldsSet["access_token_cookie"] = true
	o.AccessTokenCookie = val
}

func (o *Output) SetIdTokenCookie(val string) {
	o.fieldsSet["id_token_cookie"] = true
	o.IdTokenCookie = val
}

func (o *Output) SetRefreshTokenCookie(val string) {
	o.fieldsSet["refresh_token_cookie"] = true
	o.RefreshTokenCookie = val
}

func (o *Output) WasSet(field string) bool {
	_, found := o.fieldsSet[field]
	return found
}

// The optional credentials passed in the request
type Credentials struct {

	// Optionally contains the authn/z session cookies
	Cookies string

	// Optionally contains the authorization header
	AuthorizationHeader string
}

// A subject contains a list of attributes that identify
// the caller identity.
type Subject struct {

	// The user name/ID that the subject represents.
	User string

	// Groups the subject belongs to depending on the authentication mechanism,
	// "groups" are normally populated from JWT claim or client certificate.
	// The operator can define how it is populated when creating an instance of
	// the template.
	Groups string

	// The optional credentials passed in the request
	Credentials *Credentials

	// Additional attributes about the subject.
	Properties map[string]interface{}
}

// An action defines "how a resource is accessed".
type Action struct {

	// Namespace the target action is taking place in.
	Namespace string

	// The Service the action is being taken on.
	Service string

	// What action is being taken.
	Method string

	// HTTP REST path within the service
	Path string

	// Additional data about the action for use in policy.
	Properties map[string]interface{}
}

// HandlerBuilder must be implemented by adapters if they want to
// process data associated with the 'authnz' template.
//
// Mixer uses this interface to call into the adapter at configuration time to configure
// it with adapter-specific configuration as well as all template-specific type information.
type HandlerBuilder interface {
	adapter.HandlerBuilder

	// SetAuthnZTypes is invoked by Mixer to pass the template-specific Type information for instances that an adapter
	// may receive at runtime. The type information describes the shape of the instance.
	SetAuthnZTypes(map[string]*Type /*Instance name -> Type*/)
}

// Handler must be implemented by adapter code if it wants to
// process data associated with the 'authnz' template.
//
// Mixer uses this interface to call into the adapter at request time in order to dispatch
// created instances to the adapter. Adapters take the incoming instances and do what they
// need to achieve their primary function.
//
// The name of each instance can be used as a key into the Type map supplied to the adapter
// at configuration time via the method 'SetAuthnZTypes'.
// These Type associated with an instance describes the shape of the instance
type Handler interface {
	adapter.Handler

	// HandleAuthnZ is called by Mixer at request time to deliver instances to
	// to an adapter.
	HandleAuthnZ(context.Context, *Instance) (adapter.CheckResult, *Output, error)
}
