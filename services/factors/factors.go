package factors

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

const endpoint = "/api/v1/users/"

// Response :
// 	Response struct that will be populated after the post request.
type Response struct {
	UserID       string         `json:"user_id"`
	Status       string         `json:"status"`
	Message      string         `json:"message"`
	Factors      Factors        `json:"factors,omitempty"`
	HTTPResponse *http.Response `json:",omitempty"`
}

// Factors :
//	Struct of factor data returned by the users endpoint.
type Factors []struct {
	FactorType   string   `json:"type"`
	ID           string   `json:"id,omitempty"`
	Value        string   `json:"value"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// Request :
//	Empty Request struct to allow easy use for Get func.
type Request struct{}

// Get :
//	Executes a get to the users endpoint.
// Parameters:
//	[Required] r: empty struct used to make Get easy.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] user: the user you want to get factor information for.
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
	factorResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(factorResponse); err != nil {
		return nil, err
	}
	factorResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return factorResponse, nil
}

// buildEndpointPath:
//	non-exportable helper to build the endpoint api path with username injected.
func buildEndpointPath(user string) string {
	var buffer bytes.Buffer
	buffer.WriteString(endpoint)
	buffer.WriteString(user)
	buffer.WriteString("/factors")
	return buffer.String()
}
