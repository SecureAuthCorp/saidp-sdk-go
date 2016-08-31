package resetpassword

import (
	"net/http"
	"encoding/json"
	sa "github.com/SecureAuthCorp/saidp-sdk-go"
	"bytes"
)

/*
**********************************************************************
*   @author jhickman@secureauth.com
*
*  Copyright (c) 2016, SecureAuth
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
	endpoint = "/api/v1/users/"
)

// Summary:
//	Response struct that will be populated after the post request.

type Response struct {
	Status		string		`json:"status,omitempty"`
	Message		string		`json:"message,omitempty"`
	HttpResponse	*http.Response	`json:"-,omitempty"`
}

// Summary:
//	Request struct to build the required post parameters.
// Fields:
//	Password: password you wish to reset the user's password to.

type Request struct {
	Password	string		`json:"password"`
}

// Summary:
//	Executes a post to the users endpoint.
// Parameters:
// 	r: should have all required fields of the struct populated before using.
// 	c: passing in the client containing authorization and host information.
//	userId: the username of the user to perform the post for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) Post(c *sa.Client, userId string)(*Response, error){
	endpoint := buildEndpointPath(userId)
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
	resetResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(resetResponse); err != nil {
		return nil, err
	}
	resetResponse.HttpResponse = httpResponse
	httpResponse.Body.Close()
	return resetResponse, nil
}

// Summary:
//	Helper function for making Reset Password posts to the users endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the username of the user to perform the post for.
//	[Required] password: the password you wish to reset to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ResetPassword(c *sa.Client, userId string, password string)(*Response, error){
	r.Password = password
	resetResponse, err := r.Post(c, userId)
	if err != nil {
		return nil, err
	}
	return resetResponse, nil
}

// Summary:
//	non-exportable helper to build the endpoint api path with userid injected.

func buildEndpointPath(userId string) string {
	var buffer bytes.Buffer
	buffer.WriteString(endpoint)
	buffer.WriteString(userId)
	buffer.WriteString("/resetpwd")
	return buffer.String()
}