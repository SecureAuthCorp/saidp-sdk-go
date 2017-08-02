package profile

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
//	Response struct that will be populated after the post request.
type Response struct {
	UserID          string                        `json:"userId,omitempty"`
	Props           map[string]PropertiesResponse `json:"properties,omitempty"`
	KnowledgeBase   map[string]KnowledgeBaseData  `json:"knowledgeBase,omitempty"`
	Groups          []string                      `json:"groups,omitempty"`
	AccessHistories []AccessHistories             `json:"accessHistories,omitempty"`
	Status          string                        `json:"status,omitempty"`
	Message         string                        `json:"message,omitempty"`
	HTTPResponse    *http.Response                `json:"-"`
}

// Request :
//	Request struct to build the required post/put parameters.
// Fields:
//	Props: Set of key/value properties that you wish to update, none are required, but do not pass empty string
// 	if you want to leave the value as it is.
//	KnowledgeBase: Struct providing scaffolding to build knowledge base questions and answers.
type Request struct {
	UserID        string             `json:"userId,omitempty"`
	Password      string             `json:"password,omitempty"`
	Props         *PropertiesRequest `json:"properties,omitempty"`
	KnowledgeBase *KnowledgeBase     `json:"knowledgeBase,omitempty"`
}

// PropertiesResponse :
//	Response struct containing the attributes of a property.
type PropertiesResponse struct {
	Value       string `json:"value,omitempty"`
	IsWritable  string `json:"isWritable,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// PropertiesRequest :
//	Request struct to build the property key/value pairs.
type PropertiesRequest struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Phone1    string `json:"phone1,omitempty"`
	Phone2    string `json:"phone2,omitempty"`
	Phone3    string `json:"phone3,omitempty"`
	Phone4    string `json:"phone4,omitempty"`
	Email1    string `json:"email1,omitempty"`
	Email2    string `json:"email2,omitempty"`
	Email3    string `json:"email3,omitempty"`
	Email4    string `json:"email4,omitempty"`
	PinHash   string `json:"pinHash,omtempty"`
	AuxID1    string `json:"auxId1,omitempty"`
	AuxID2    string `json:"auxId2,omitempty"`
	AuxID3    string `json:"auxId3,omitempty"`
	AuxID4    string `json:"auxId4,omitempty"`
	AuxID5    string `json:"auxId5,omitempty"`
	AuxID6    string `json:"auxId6,omitempty"`
	AuxID7    string `json:"auxId7,omitempty"`
	AuxID8    string `json:"auxId8,omitempty"`
	AuxID9    string `json:"auxId9,omitempty"`
	AuxID10   string `json:"auxId10,omitempty"`
}

// KnowledgeBaseData :
//	Request and Response struct containing the specific knowledge base question and answer set.
type KnowledgeBaseData struct {
	Question string `json:"question,omitempty"`
	Answer   string `json:"answer,omitempty"`
}

// KnowledgeBase :
//	Request struct to build the scaffolding for the knowledge base questions and answers.
type KnowledgeBase struct {
	Kbq1       *KnowledgeBaseData `json:"kbq1,omitempty"`
	Kbq2       *KnowledgeBaseData `json:"kbq2,omitempty"`
	Kbq3       *KnowledgeBaseData `json:"kbq3,omitempty"`
	Kbq4       *KnowledgeBaseData `json:"kbq4,omitempty"`
	Kbq5       *KnowledgeBaseData `json:"kbq5,omitempty"`
	Kbq6       *KnowledgeBaseData `json:"kbq6,omitempty"`
	HelpDeskKb *KnowledgeBaseData `json:"helpDeskKb,omitempty"`
}

// AccessHistories :
//	Response struct containing the access history detaisl for the user.
type AccessHistories struct {
	UserAgent string `json:"userAgent,omitempty"`
	IPAddress string `json:"ipAddress,omitempty"`
	TimeStamp string `json:"timeStamp,omitempty"`
	AuthState string `json:"authState,omitempty"`
}

// Get :
//	Executes a get request against the users endpoint.
// Parameters:
//	[Required] r: empty struct used to make Get easy.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user to perform the get for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Get(c *sa.Client, userID string) (*Response, error) {
	endpoint := buildEndpointPath(userID)
	httpRequest, err := c.BuildGetRequest(endpoint)
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	profileResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(profileResponse); err != nil {
		return nil, err
	}
	profileResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return profileResponse, nil
}

// Post :
//	Executes a post to the users endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user to perform the post for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Post(c *sa.Client, userID string) (*Response, error) {
	endpoint := buildEndpointPath(userID)
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
	profileResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(profileResponse); err != nil {
		return nil, err
	}
	profileResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return profileResponse, nil
}

// Put :
//	Executes a put to the users endpoint.
// Parameters:
//	[Required] r: should have all the required fields for the put type.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username of the user to perform the put for.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Put(c *sa.Client, userID string) (*Response, error) {
	endpoint := buildEndpointPath(userID)
	jsonRequest, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	httpRequest, err := c.BuildPutRequest(endpoint, string(jsonRequest))
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	profileResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(profileResponse); err != nil {
		return nil, err
	}
	profileResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return profileResponse, nil
}

// CreateUser :
//	Creates a new user using the users endpoint via post.
// Parameters:
//	[Required] r: should have all the fields that are required for create user (UserId and Password at a minimum).
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) CreateUser(c *sa.Client) (*Response, error) {
	if len(r.UserID) <= 0 {
		return nil, errors.New("UserId is a required parameter for creating new users")
	}
	if len(r.Password) <= 0 {
		return nil, errors.New("UserId is a required parameter for creating new users")
	}
	profileResponse, err := r.Post(c, "")
	if err != nil {
		return nil, err
	}
	return profileResponse, nil
}

// buildEndpointPath :
//	non-exportable helper to build the endpoint api path with userid injected.
func buildEndpointPath(userID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(endpoint)
	buffer.WriteString(userID)
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
