package throttle

import (
	"bytes"
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
	usersEndpoint = "/api/v1/users/"
)

// Request :
//	Empty Request struct for easy function access.
type Request struct {
}

// Response :
//	Response struct that will be populated after the request.
type Response struct {
	Status       string         `json:"status,omitempty"`
	Message      string         `json:"message,omitempty"`
	Count        int            `json:"count,omitempty"`
	HTTPResponse *http.Response `json:"-,omitempty"`
}

// Get :
//	Executes a post to the users throttle/ endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] user: the user id of the user you wish to get the throttle status for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Get(c *sa.Client, user string) (*Response, error) {
	endpoint := buildEndpointPath(user)
	httpRequest, err := c.BuildGetRequest(endpoint)
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	throttleResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(throttleResponse); err != nil {
		return nil, err
	}
	throttleResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return throttleResponse, nil
}

// Put :
//	Executes a put request to the users throttle/ endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] user: the user id of the user you wish to reset the throttle status for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Put(c *sa.Client, user string) (*Response, error) {
	endpoint := buildEndpointPath(user)
	httpRequest, err := c.BuildEmptyPutRequest(endpoint)
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	throttleResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(throttleResponse); err != nil {
		return nil, err
	}
	throttleResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return throttleResponse, nil
}

// buildEndpointPath :
//	non-exportable helper to build the endpoint api path with username injected.
func buildEndpointPath(user string) string {
	var buffer bytes.Buffer
	buffer.WriteString(usersEndpoint)
	buffer.WriteString(user)
	buffer.WriteString("/throttle")
	return buffer.String()
}
