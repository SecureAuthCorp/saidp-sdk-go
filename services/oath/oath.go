package oath

import (
	"encoding/json"
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

const endpoint = "/api/v1/oath"

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	ServerTime    string         `json:"server_time,omitempty"`
	Key           string         `json:"key,omitempty"`
	Interval      string         `json:"interval,omitempty"`
	Length        string         `json:"length,omitempty"`
	Offset        string         `json:"offset,omitempty"`
	PinControl    string         `json:"pin_control,omitempty"`
	FailedWipe    string         `json:"failed_wipe,omitempty"`
	ScreenTimeout string         `json:"screen_timeout,omitempty"`
	HTTPResponse  *http.Response `json:",omitempty"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to submit access history for.
//	[Required] Password: The password of the user you are retrieving oath settings for.
//	[Required] Token: The otp of the user you are retrieving oath settings for.
//	[Required] FactorID: The id of the device you are retrieving oath settings for.
type Request struct {
	UserID   string `json:"user_id,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	FactorID string `json:"factor_id,omitempty"`
}

// Post :
//	Executes a post to the oath endpoint.
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
	oathResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(oathResponse); err != nil {
		return nil, err
	}
	oathResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return oathResponse, nil
}

// GetOATHSettings :
//	Helper function to retrieve the oath settings for a given user.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user whose oath settings you want.
//	[Required] password: the password of the user whose oath settings you want.
//	[Required] otp: the otp of the user whose oath settings you want.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) GetOATHSettings(c *sa.Client, userID string, password string, otp string, id string) (*Response, error) {
	r.UserID = userID
	r.Password = password
	r.Token = otp
	r.FactorID = id
	oathResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return oathResponse, nil
}
