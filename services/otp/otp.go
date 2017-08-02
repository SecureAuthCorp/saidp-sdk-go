package otp

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
*   @author scox@secureauth.com
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

const endpoint = "/api/v1/otp/validate"

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	Status       string         `json:"status,omitempty"`
	Message      string         `json:"message,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	HTTPResponse *http.Response `json:"-,omitempty"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: The username that you want to validate an otp for.
//	[Required] Domain: The domain of the user you want to validate an otp for.
//	[Required] OTP: The OTP you want to validate.
type Request struct {
	UserID string `json:"user_id"`
	Domain string `json:"domain,omitempty"`
	OTP    string `json:"otp"`
}

// Post :
//	Executes a post to the otp endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
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
	otpResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(otpResponse); err != nil {
		return nil, err
	}
	otpResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return otpResponse, nil
}

// ValidateOTP :
//	Helper function for making Validate otp auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] domain: the domain of the user you wish to validate. (optional)
//	[Required] otp: the otp to be validated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateOTP(c *sa.Client, userID string, domain string, otp string) (*Response, error) {
	r.UserID = userID
	r.Domain = domain
	r.OTP = otp
	otpResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return otpResponse, nil
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
	responseBody, err := ioutil.ReadAll(r.HTTPResponse.Body)
	if err != nil {
		return false, err
	}
	responseString := string(responseBody)
	var buffer bytes.Buffer
	buffer.WriteString(saDate)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(responseString)
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
