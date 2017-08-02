package adaptauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

const endpoint = "/api/v1/adaptauth"

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	RealmWorkflow   string         `json:"realm_workflow,omitempty"`
	SuggestedAction string         `json:"suggested_action,omitempty"`
	RedirectURL     string         `json:"redirect_url,omitempty"`
	Status          string         `json:"status,omitempty"`
	Message         string         `json:"message,omitempty"`
	HTTPResponse    *http.Response `json:"-"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to evaluate.
//	[Required] Params: struct for required post params.
type Request struct {
	UserID string     `json:"user_id"`
	Params Parameters `json:"parameters"`
}

// Parameters :
//	Parameters struct for post params needed for adapt auth endpoint.
// Fields:
//	[Required] IpAddress: Ip Address of the user to be evaluated.
type Parameters struct {
	IPAddress string `json:"ip_address"`
}

// Post :
//	Executes a post to the adaptauth endpoint.
// Parameters:
// 	[Required] r: should have all the required fields of the struct populated before using.
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Post(c *sa.Client) (*Response, error) {
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
	adaptResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(adaptResponse); err != nil {
		return nil, err
	}
	adaptResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return adaptResponse, nil
}

// EvaluateAdaptiveAuth :
//	Helper function for making Adaptive Auth Posts
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the user you wish to evaluate via adaptive auth.
//	[Required] ipAddress: the ip address of the user being evaluated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) EvaluateAdaptiveAuth(c *sa.Client, userID string, ipAddress string) (*Response, error) {
	r.UserID = userID
	r.Params.IPAddress = ipAddress
	adaptResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return adaptResponse, nil
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
	jsonResponse, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(saDate)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(string(jsonResponse))
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
