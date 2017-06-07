package accesshistory

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

const endpoint = "/api/v1/accesshistory"

// Response :
// 	Response struct that will be populated after the post request.
type Response struct {
	Status       string         `json:"status,omitempty"`
	Message      string         `json:"message,omitempty"`
	HTTPResponse *http.Response `json:",omitempty"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to submit access history for.
//	[Required] IpAddress:  ip address the user is connecting from that you wish to record the history of.
type Request struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
}

// Post :
//	Executes a post to the access history endpoint.
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
	accessResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(accessResponse); err != nil {
		return nil, err
	}
	accessResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return accessResponse, nil
}

// SetAccessHistory :
//	Helper function for making Access History Posts
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the user you wish to submit the access history for.
//	[Required] ipAddress: the ip address of the authentication you want to record.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SetAccessHistory(c *sa.Client, userID string, ipAddress string) (*Response, error) {
	r.UserID = userID
	r.IPAddress = ipAddress
	aHistoryResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return aHistoryResponse, nil
}
