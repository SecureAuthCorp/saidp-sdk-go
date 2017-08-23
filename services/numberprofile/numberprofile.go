package numberprofile

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

const endpoint = "/api/v1/numberprofile"

// Response :
//  Response struct that will be populated after the request.
type Response struct {
	Status       string         `json:"status"`
	Message      string         `json:"message"`
	Result       Result         `json:"numberProfileResult,omitempty"`
	RawJSON      string         `json:"-"`
	HTTPResponse *http.Response `json:"-"`
}

// Request :
//  Request struct to build the required post and put parameters.
// Fields:
//  [Required] UserID: the username that you want to evaluate the number on behalf of.
//  [Required] PhoneNumber: the phone number of the user to be evaluated.
//  CarrierInfo: Used in PUT operations to update the currentCarrier of the numberProfile.
type Request struct {
	UserID      string      `json:"user_id"`
	PhoneNumber string      `json:"phone_number"`
	CarrierInfo CarrierInfo `json:"carrierInfo,omitempty"`
}

// Result :
//  Struct for NumberProfileResult data.
type Result struct {
	ProviderRequestID   string          `json:"providerRequestId,omitempty"`
	InternationalFormat string          `json:"internationalFormat,omitempty"`
	NationalFormat      string          `json:"nationalFormat,omitempty"`
	CountryPrefix       string          `json:"countryPrefix,omitempty"`
	CountryCode         string          `json:"countryCode,omitempty"`
	CountryCodeISO3     string          `json:"countryCodeISO3,omitempty"`
	Country             string          `json:"country,omitempty"`
	PortedStatus        string          `json:"portedStatus,omitempty"`
	ValidNumber         interface{}     `json:"validNumber,omitempty"`
	Reachable           interface{}     `json:"reachable,omitempty"`
	RoamingInfo         interface{}     `json:"roamingInfo,omitempty"`
	CurrentCarrier      CurrentCarrier  `json:"currentCarrier,omitempty"`
	OriginalCarrier     OriginalCarrier `json:"originalCarrier,omitempty"`
	IPInfo              interface{}     `json:"ipInfo,omitempty"`
	IPWarning           interface{}     `json:"ipWarning,omitempty"`
}

// CurrentCarrier :
//  Struct for CurrentCarrier data.
type CurrentCarrier struct {
	CarrierCode   string        `json:"carrierCode,omitempty"`
	Carrier       string        `json:"carrier,omitempty"`
	CountryCode   string        `json:"countryCode,omitempty"`
	NetworkType   string        `json:"networkType,omitempty"`
	CarrierStatus CarrierStatus `json:"carrierStatus,omitempty"`
}

// OriginalCarrier :
//  Struct for OriginalCarrier data.
type OriginalCarrier struct {
	CarrierCode   string        `json:"carrierCode,omitempty"`
	Carrier       string        `json:"carrier,omitempty"`
	CountryCode   string        `json:"countryCode,omitempty"`
	NetworkType   string        `json:"networkType,omitempty"`
	CarrierStatus CarrierStatus `json:"carrierStatus,omitempty"`
}

// CarrierStatus :
//  Struct for CarrierStatus
type CarrierStatus struct {
	Status string      `json:"status,omitempty"`
	Reason interface{} `json:"reason,omitempty"`
}

// CarrierInfo :
// Struct for CarrierInfo used in put request to update CurrentCarrier
type CarrierInfo struct {
	CarrierCode string `json:"carrierCode,omitempty"`
	Carrier     string `json:"carrier,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	NetworkType string `json:"networkType,omitempty"`
}

// Post :
//  Executes a post to the numberprofile endpoint.
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
	numberProfileResponse := new(Response)
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, numberProfileResponse); err != nil {
		return nil, err
	}
	numberProfileResponse.RawJSON = string(body)
	httpResponse.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	numberProfileResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return numberProfileResponse, nil
}

// Put :
//  Executes a put to the numberprofile endpoint.
// Parameters:
//	[Required] r: should have all the required fields for the put type.
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] endpoint: the endpoint for the put request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Put(c *sa.Client) (*Response, error) {
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
	numberProfileResponse := new(Response)
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, numberProfileResponse); err != nil {
		return nil, err
	}
	numberProfileResponse.RawJSON = string(body)
	httpResponse.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	numberProfileResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return numberProfileResponse, nil
}

// EvaluateNumberProfile :
//  Helper function for posting to the numberprofile endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username that you want to evaluate the number on behalf of.
//  [Required] phoneNumber: the phone number of the user to be evaluated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) EvaluateNumberProfile(c *sa.Client, userID string, phoneNumber string) (*Response, error) {
	r.UserID = userID
	r.PhoneNumber = phoneNumber
	numberProfileResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return numberProfileResponse, nil
}

// UpdateCurrentCarrier :
//  Helper function for putting to the numberprofile endpoint.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the username that you want to evaluate the number on behalf of.
//  [Required] phoneNumber: the phone number of the user to be evaluated.
//  [Required] carrierCode: the carrier code of the current carrier you wish to save.
//  [Required] carrier: the carrier of the current carrier you wish to save.
//  [Required] countryCode: the country code of the current carrier you wish to save.
//  [Required] networkType: the network type of the current carrier you wish to save.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) UpdateCurrentCarrier(c *sa.Client, userID string, phoneNumber string, carrierCode string, carrier string, countryCode string, networkType string) (*Response, error) {
	r.UserID = userID
	r.PhoneNumber = phoneNumber
	r.CarrierInfo = CarrierInfo{CarrierCode: carrierCode, Carrier: carrier, CountryCode: countryCode, NetworkType: networkType}
	numberProfileResponse, err := r.Put(c)
	if err != nil {
		return nil, err
	}
	return numberProfileResponse, nil
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
