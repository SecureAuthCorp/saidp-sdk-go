package groups

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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
	usersEndpoint  = "/api/v1/users/"
	groupsEndpoint = "/api/v1/groups/"
)

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	Status       string              `json:"status,omitempty"`
	Message      string              `json:"message,omitempty"`
	Failures     map[string][]string `json:"failures,omitempty"`
	HTTPResponse *http.Response      `json:"-"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	UserIds: usernames of the users you want to add to a single group.
//	GroupNames: names of the groups you want to add a single user to.
type Request struct {
	UserIds    []string `json:"userIds,omitempty"`
	GroupNames []string `json:"groupNames,omitempty"`
}

// Post :
//	Executes a post to the users or groups endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] endpoint: the endpoint perform the post to.
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
	groupsResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(groupsResponse); err != nil {
		return nil, err
	}
	groupsResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return groupsResponse, nil
}

// AddUserToGroup :
//	Helper function for making user posts to add a single user to a single group.
// Parameters:
//	[Required] r: should be empty for this call.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user to add to a group.
//	[Required] groupid: the name of the group to add a user to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.\
func (r *Request) AddUserToGroup(c *sa.Client, userID string, groupID string) (*Response, error) {
	endpoint := buildSingleUserToSingleGroupEndpoint(userID, groupID)
	groupsResponse, err := r.Post(c, endpoint)
	if err != nil {
		return nil, err
	}
	return groupsResponse, nil
}

// AddUserToGroups :
//	Helper function for making user posts to add a single user to multiple groups.
// Parameters:
//	[Required] r: should be empty for this call.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user to add to multiple groups.
//	[Required] groups: a string slice of group names to add the user to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) AddUserToGroups(c *sa.Client, userID string, groups []string) (*Response, error) {
	r.GroupNames = groups
	endpoint := buildSingleUserToMultiGroupEndpoint(userID)
	groupsResponse, err := r.Post(c, endpoint)
	if err != nil {
		return nil, err
	}
	return groupsResponse, nil
}

// AddGroupToUser :
//	Helper function for making user posts to add a single group to a single single.
// Parameters:
//	[Required] r: should be empty for this call.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] groupid: the name of the group to add a user to.
//	[Required] userID: the username of the user to add to a group.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) AddGroupToUser(c *sa.Client, groupID string, userID string) (*Response, error) {
	endpoint := buildSingleGroupToSingleUserEndpoint(groupID, userID)
	groupsResponse, err := r.Post(c, endpoint)
	if err != nil {
		return nil, err
	}
	return groupsResponse, nil
}

// AddGroupToUsers :
//	Helper function for making user posts to add a single group to multiple users.
// Parameters:
//	[Required] r: should be empty for this call.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] groupID: the name of the group to add to each user.
//	[Required] users: a string slice of usernames to add to the group.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) AddGroupToUsers(c *sa.Client, groupID string, users []string) (*Response, error) {
	r.UserIds = users
	endpoint := buildSingleGroupToMultiUsersEndpoint(groupID)
	groupsResponse, err := r.Post(c, endpoint)
	if err != nil {
		return nil, err
	}
	return groupsResponse, nil
}

// buildSingleUserToSingleGroupEndpoint :
//	non-exportable helper to build the endpoint api path with userid injected.
func buildSingleUserToSingleGroupEndpoint(userID string, groupID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(usersEndpoint)
	buffer.WriteString(userID)
	buffer.WriteString("/groups/")
	u := &url.URL{Path: groupID}
	escapedGroup := u.String()
	buffer.WriteString(escapedGroup)
	fmt.Println(buffer.String())
	return buffer.String()
}

// buildSingleGroupToMultiUsersEndpoint :
//	non-exportable helper to build the endpoint api path with userid injected.
func buildSingleGroupToMultiUsersEndpoint(groupID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(groupsEndpoint)
	u := &url.URL{Path: groupID}
	escapedGroup := u.String()
	buffer.WriteString(escapedGroup)
	buffer.WriteString("/users")
	return buffer.String()
}

// buildSingleGroupToSingleUserEndpoint :
//	non-exportable helper to build the endpoint api path with userid injected.
func buildSingleGroupToSingleUserEndpoint(groupID string, userID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(groupsEndpoint)
	u := &url.URL{Path: groupID}
	escapedGroup := u.String()
	buffer.WriteString(escapedGroup)
	buffer.WriteString("/users/")
	buffer.WriteString(userID)
	return buffer.String()
}

// buildSingleUserToMultiGroupEndpoint :
//	non-exportable helper to build the endpoint api path with userid injected.
func buildSingleUserToMultiGroupEndpoint(userID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(usersEndpoint)
	buffer.WriteString(userID)
	buffer.WriteString("/groups")
	return buffer.String()
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
