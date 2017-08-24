package dfp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
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
	saveEndpoint    = "/api/v1/dfp/save"
)

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	FingerprintID   string         `json:"fingerprint_id,omitempty"`
	FingerprintName string         `json:"fingerprint_name,omitempty"`
	Score           string         `json:"score,omitempty"`
	MatchScore      string         `json:"match_score,omitempty"`
	UpdateScore     string         `json:"update_score,omitempty"`
	Status          string         `json:"status"`
	Message         string         `json:"message"`
	UserID          string         `json:"user_id,omitempty"`
	Source          string         `json:"src,omitempty"`
	RawJSON         string         `json:"-"`
	HTTPResponse    *http.Response `json:"-"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserID: the username that you wish to validate a fingerprint for.
//	HostAddress: the IP Address of the user.
//	FingerprintID: used to validate known fingerprint or confirm a fingerprint.
//	Fingerprint: fingerprint value struct required to validate a fingerprint.
type Request struct {
	UserID        string                 `json:"user_id,omitempty"`
	HostAddress   string                 `json:"host_address,omitempty"`
	FingerprintID string                 `json:"fingerprint_id,omitempty"`
	Fingerprint   map[string]interface{} `json:"fingerprint,omitempty"`
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
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, dfpResponse); err != nil {
		return nil, err
	}
	dfpResponse.RawJSON = string(body)
	httpResponse.Body = ioutil.NopCloser(bytes.NewBuffer(body))
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
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, dfpResponse); err != nil {
		return nil, err
	}
	dfpResponse.RawJSON = string(body)
	httpResponse.Body = ioutil.NopCloser(bytes.NewBuffer(body))
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
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string) (*Response, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(fingerprint), &m); err != nil {
		return nil, err
	}
	r.Fingerprint = m
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
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ScoreDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string) (*Response, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(fingerprint), &m); err != nil {
		return nil, err
	}
	r.Fingerprint = m
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
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SaveDfp(c *sa.Client, userID string, hostAddress string, fingerprintID string, fingerprint string) (*Response, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(fingerprint), &m); err != nil {
		return nil, err
	}
	r.Fingerprint = m
	r.FingerprintID = fingerprintID
	r.UserID = userID
	r.HostAddress = hostAddress
	validateResponse, err := r.Post(c, saveEndpoint)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}

//IsSignatureValid :
//	Helper function to validate the SecureAuth Response signature in X-SA-SIGNATURE
// Parameters:
//	[Required] r: response struct with HTTPResponse
//	[Required] c: passing in the client with application id and key
// Returns:
//	bool: if true, computed signature matches X-SA-SIGNATURE. if false, computed signature does not match.
//	error: If an error is encountered, bool will be false and the error must be handled.
func (r *Response) IsSignatureValid(c *sa.Client) (bool, error) {
	saDate := r.HTTPResponse.Header.Get("X-SA-DATE")
	saSignature := r.HTTPResponse.Header.Get("X-SA-SIGNATURE")
	var buffer bytes.Buffer
	buffer.WriteString(saDate)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(r.RawJSON)
	raw := buffer.String()
	byteKey, _ := hex.DecodeString(c.AppKey)
	byteData := []byte(raw)
	sig := hmac.New(sha256.New, byteKey)
	sig.Write([]byte(byteData))
	computedSig := base64.StdEncoding.EncodeToString(sig.Sum(nil))
	if computedSig != saSignature {
		return false, nil
	}
	return true, nil
}
