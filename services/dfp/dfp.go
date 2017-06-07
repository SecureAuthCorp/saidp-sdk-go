package dfp

import (
	"encoding/json"
	"net/http"

	sa "github.com/secureauthcorp/saidp-sdk-go"
)

/*
**********************************************************************
*   @author jhickman@secureauth.com
*
*  Copyright (c) 2017, SecureAuth
*  All rights reserved.
*
*    Redistribution and use in source and binary forms, with or without modification,
*    are permitted provided that the following conditions are met:
*
*    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
*
*    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
*    in the documentation and/or other materials provided with the distribution.
*
*    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
*    from this software without specific prior written permission.
*
*    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
*    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
*    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
*    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
*    EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************
 */

const (
	jsEndpoint      = "/api/v1/dfp/js"
	valEndpoint     = "/api/v1/dfp/validate"
	confirmEndpoint = "/api/v1/dfp/confirm"
	scoreEndpoint   = "/api/v1/dfp/score"
	saveEndpoint    = "ap1/v1/dfp/save"
)

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	FingerprintID   string         `json:"fingerprint_id,omitempty"`
	FingerprintName string         `json:"fingerprint_name,omitempty"`
	Score           string         `json:"score,omitempty"`
	MatchScore      string         `json:"match_score,omitempty"`
	UpdateScore     string         `json:"update_score,omitempty"`
	Status          string         `json:"status,omitempty"`
	Message         string         `json:"message,omitempty"`
	UserID          string         `json:"user_id,omitempty"`
	Source          string         `json:"src,omitempty"`
	HTTPResponse    *http.Response `json:",omitempty"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserID: the username that you wish to validate a fingerprint for.
//	HostAddress: the IP Address of the user.
//	FingerprintID: used to validate known fingerprint or confirm a fingerprint.
//	Fingerprint: fingerprint value struct required to validate a fingerprint.
type Request struct {
	UserID        string      `json:"user_id,omitempty"`
	HostAddress   string      `json:"host_address,omitempty"`
	FingerprintID string      `json:"fingerprint_id,omitempty"`
	Fingerprint   Fingerprint `json:"fingerprint,omitempty"`
}

// Fingerprint :
//	Details for the fingerprint makeup.
// Fields:
//	All fields should be populated from the Json string returned by the imported javascript.
type Fingerprint struct {
	Fonts          string `json:"fonts,omitempty"`
	Plugins        string `json:"plugins,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	Video          string `json:"video,omitempty"`
	LocalStorage   string `json:"local_storage,omitempty"`
	SessionStorage string `json:"session_storage,omitempty"`
	IeUserData     string `json:"ie_user_data,omitempty"`
	CookieEnabled  string `json:"cookie_enabled,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	Accept         string `json:"accept,omitempty"`
	AcceptCharset  string `json:"accept_charset,omitempty"`
	AcceptEncoding string `json:"accept_encoding,omitempty"`
	AcceptLang     string `json:"accept_language,omitempty"`
}

// Get :
//	Executes a get to the dfp/js endpoint.
// Parameters:
//	[Required] r: struct used to perform get request.
//	[Required] c: passing in the client containing authorization and host information.
//	endpoint: the endpoint for the get request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Get(c *sa.Client, endpoint string) (*Response, error) {
	httpRequest, err := c.BuildGetRequest(endpoint)
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	dfpResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(dfpResponse); err != nil {
		return nil, err
	}
	dfpResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return dfpResponse, nil
}

// Post :
//	Executes a post to the dfp endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] endpoint: the endpoint for the post request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Post(c *sa.Client, endpoint string) (*Response, error) {
	jsonRequest, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	httpRequest, err := c.BuildPostRequest(endpoint, string(jsonRequest))
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	dfpResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(dfpResponse); err != nil {
		return nil, err
	}
	dfpResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return dfpResponse, nil
}

// GetDfpJs :
//	Helper function for Get request to retrieve the fingerprint javascript source.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) GetDfpJs(c *sa.Client) (*Response, error) {
	dpfResponse, err := r.Get(c, jsEndpoint)
	if err != nil {
		return nil, err
	}
	return dpfResponse, nil
}

// ValidateDfp :
//	Helper function for posting to the dfp validate endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user you wish to validate a dfp for.
//	[Required] hostAddress: the ip address of the user's device.
//	fingerprintId: if it is a known fingerprint, provide the fingerprint id to validate against.
//	[Required] fingerprint: the json string returned by the javascript dfp script.
//	[Required] accept: accept header of the users request.
//	[Required] acceptCharset: the accept_charset header of the users request.
//	[Required] acceptEncoding: the accept_encoding header of the users request.
//	[Required] acceptLanguage: the accept_language header of the users request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string, accept string, acceptCharset string, acceptEncoding string, acceptLanguage string) (*Response, error) {
	if err := json.Unmarshal([]byte(fingerprint), &r); err != nil {
		return nil, err
	}
	r.Fingerprint.Accept = accept
	r.Fingerprint.AcceptCharset = acceptCharset
	r.Fingerprint.AcceptEncoding = acceptEncoding
	r.Fingerprint.AcceptLang = acceptLanguage
	r.FingerprintID = fingerprintID
	r.UserID = userID
	r.HostAddress = hostAddress
	validateResponse, err := r.Post(c, valEndpoint)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}

// ConfirmDfp :
//	Helper function for posting to the dfp validate endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user you wish to confirm a dfp for.
//	[Required] fingerprintId: the fingerprint id of the fingerprint you wish to confirm.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ConfirmDfp(c *sa.Client, userID string, fingerprintID string) (*Response, error) {
	r.UserID = userID
	r.FingerprintID = fingerprintID
	confirmResponse, err := r.Post(c, confirmEndpoint)
	if err != nil {
		return nil, err
	}
	return confirmResponse, nil
}

// ScoreDfp :
//	Helper function for posting to the dfp validate endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user you wish to validate a dfp for.
//	[Required] hostAddress: the ip address of the user's device.
//	fingerprintId: if it is a known fingerprint, provide the fingerprint id to validate against.
//	[Required] fingerprint: the json string returned by the javascript dfp script.
//	[Required] accept: accept header of the users request.
//	[Required] acceptCharset: the accept_charset header of the users request.
//	[Required] acceptEncoding: the accept_encoding header of the users request.
//	[Required] acceptLanguage: the accept_language header of the users request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ScoreDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string, accept string, acceptCharset string, acceptEncoding string, acceptLanguage string) (*Response, error) {
	if err := json.Unmarshal([]byte(fingerprint), &r); err != nil {
		return nil, err
	}
	r.Fingerprint.Accept = accept
	r.Fingerprint.AcceptCharset = acceptCharset
	r.Fingerprint.AcceptEncoding = acceptEncoding
	r.Fingerprint.AcceptLang = acceptLanguage
	r.FingerprintID = fingerprintID
	r.UserID = userID
	r.HostAddress = hostAddress
	validateResponse, err := r.Post(c, scoreEndpoint)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}

// SaveDfp :
//	Helper function for posting to the dfp validate endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user you wish to validate a dfp for.
//	[Required] hostAddress: the ip address of the user's device.
//	fingerprintId: if it is a known fingerprint, provide the fingerprint id to validate against.
//	[Required] fingerprint: the json string returned by the javascript dfp script.
//	[Required] accept: accept header of the users request.
//	[Required] acceptCharset: the accept_charset header of the users request.
//	[Required] acceptEncoding: the accept_encoding header of the users request.
//	[Required] acceptLanguage: the accept_language header of the users request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SaveDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string, accept string, acceptCharset string, acceptEncoding string, acceptLanguage string) (*Response, error) {
	if err := json.Unmarshal([]byte(fingerprint), &r); err != nil {
		return nil, err
	}
	r.Fingerprint.Accept = accept
	r.Fingerprint.AcceptCharset = acceptCharset
	r.Fingerprint.AcceptEncoding = acceptEncoding
	r.Fingerprint.AcceptLang = acceptLanguage
	r.FingerprintID = fingerprintID
	r.UserID = userID
	r.HostAddress = hostAddress
	validateResponse, err := r.Post(c, saveEndpoint)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}
