package auth

import (
	"net/http"
	sa "github.com/SecureAuthCorp/saidp-sdk-go"
	"encoding/json"
	"bytes"
	"time"
	"errors"
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

const endpoint = "/api/v1/auth"

// Summary:
//	Response struct that will be populated after the post request.

type Response struct {
	RefId		string			`json:"reference_id,omitempty"`
	Status		string			`json:"status,omitempty"`
	Message		string			`json:"message,omitempty"`
	UserId		string			`json:"user_id,omitempty"`
	Otp		string			`json:"otp,omitempty"`
	HttpResponse	*http.Response		`json:"-,omitempty"`
}

// Summary:
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to submit access history for.
//	[Required] ReqType: type of auth request, valid entries: user_id, password, kba, oath,
// 		   pin, call, sms, email, push, push_accept, help_desk
//	Token: used to pass data for validation
//	[Required] FactorId: identifier to which attribute in the users profile the request type
// 		   should use. Also referred to as device id.
//	PushDetails: if ReqType is push_accept, push details will allow details of the auth attempt
//		   to be sent with the push request.

type Request struct {
	UserId		string			`json:"user_id"`
	ReqType		string			`json:"type"`
	Token		string			`json:"token,omitempty"`
	FactorId	string			`json:"factor_id,omitempty"`
	PushDetails	*PushAcceptDetails	`json:"push_accept_details,omitempty"`
}

// Summary:
//	Details for the push_accept request.
// Fields:
//	CompanyName: Displayed on the push to accept request.
//	AppDesc: Displayed on the push to accept request.
//	EnduserIp: Displayed on the push to accept request.

type PushAcceptDetails struct {
	CompanyName	string			`json:"company_name"`
	AppDesc		string			`json:"application_description"`
	EnduserIp	string			`json:"enduser_ip"`
}

// Summary:
//	Executes a post to the auth endpoint.
// Parameters:
// 	[Required] r: should have all required fields of the struct populated before using.
// 	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) Post(c *sa.Client)(*Response, error) {
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
	authResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(authResponse); err != nil {
		return nil, err
	}
	authResponse.HttpResponse = httpResponse
	httpResponse.Body.Close()
	return authResponse, nil
}

// Summery:
//	Executes a get request for checking push to accept status.
// Parameters:
//	[Required] r: empty struct used to make Get easy.
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) Get(c *sa.Client, refId string)(*Response, error) {
	endpoint := buildEndpointPath(refId)
	httpRequest, err := c.BuildGetRequest(endpoint)
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	authResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(authResponse); err != nil{
		return nil, err
	}
	authResponse.HttpResponse = httpResponse
	httpResponse.Body.Close()
	return authResponse, nil
}

// Summary:
//	Helper function for making Validate User auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user you wish to validate.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ValidateUser(c *sa.Client, userId string)(*Response, error) {
	r.UserId = userId
	r.ReqType = "user_id"
	validateResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}

// Summary:
//	Helper function for making Validate Password auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user you wish to validate.
//	[Required] password: the password of the user you wish to validate.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ValidatePassword(c *sa.Client, userId string, password string)(*Response, error) {
	r.UserId = userId
	r.ReqType = "password"
	r.Token = password
	passwordResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return passwordResponse, nil
}

// Summary:
//	Helper function for making Validate Kba auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user you wish to validate.
//	[Required] answer: the answer for the kbq value you want to validate.
//	[Required] kbqId: the id of the kbq the answer will be validated against.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ValidateKba(c *sa.Client, userId string, answer string, kbqId string)(*Response, error) {
	r.UserId = userId
	r.ReqType = "kba"
	r.Token = answer
	r.FactorId = kbqId
	kbaResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return kbaResponse, nil
}

// Summary:
//	Helper function for making Validate Oath auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user you wish to validate.
//	[Required] oathOtp: the otp value to be validated.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier to which Oath is registered to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ValidateOath(c *sa.Client, userId string, oathOtp string, deviceId string)(*Response, error) {
	r.UserId = userId
	r.ReqType = "oath"
	r.Token = oathOtp
	r.FactorId = deviceId
	oathResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return oathResponse, nil
}

// Summary:
//	Helper function for making Validate Pin auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user you wish to validate.
//	[Required] pin: the pin to be validated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) ValidatePin(c *sa.Client, userId string, pin string)(*Response, error){
	r.UserId = userId
	r.ReqType = "pin"
	r.Token = pin
	pinResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pinResponse, nil
}

// Summary:
//	Helper function to send otp via phone call through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user the call will be sent to.
//	[Required] factorId: from factor_id of a user endpoint call. Identifier of the profile
//		   attribute that the call should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendCallOtp(c *sa.Client, userId string, factorId string)(*Response, error){
	r.UserId = userId
	r.ReqType = "call"
	r.FactorId = factorId
	callResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return callResponse, nil
}

// Summary:
//	Helper function to send otp via sms through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user the sms will be sent to.
//	[Required] factorId: from factor_id of a user endpoint sms. Identifier of the profile
//		   attribute that the sms should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendSMSOtp(c *sa.Client, userId string, factorId string)(*Response, error){
	r.UserId = userId
	r.ReqType = "sms"
	r.FactorId = factorId
	smsResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return smsResponse, nil
}

// Summary:
//	Helper function to send otp via email through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user the email will be sent to.
//	[Required] factorId: from factor_id of a user endpoint email. Identifier of the profile
//		   attribute that the email should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendEmailOtp(c *sa.Client, userId string, factorId string)(*Response, error){
	r.UserId = userId
	r.ReqType = "email"
	r.FactorId = factorId
	emailResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return emailResponse, nil
}

// Summary:
//	Helper function to send otp via push notification through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user the push notification will be sent to.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier which is registered.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendPushNotify(c *sa.Client, userId string, deviceId string)(*Response, error){
	r.UserId = userId
	r.ReqType = "push"
	r.FactorId = deviceId
	pushResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pushResponse, nil
}

// Summary:
//	Helper function to send otp via push notification through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user the push to accept will be sent to.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier which is registered.
//	companyName: Displayed on the push to accept request.
//	appDesc: Displayed on the push to accept request.
//	userIp: Displayed on the push to accept request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendPushAccept(c *sa.Client, userId string, deviceId string, companyName string, appDesc string, userIp string)(*Response, error){
	r.UserId = userId
	r.ReqType = "push_accept"
	r.FactorId = deviceId
	pushDetails := new(PushAcceptDetails)
	pushDetails.CompanyName = companyName
	pushDetails.AppDesc = appDesc
	pushDetails.EnduserIp = userIp
	r.PushDetails = pushDetails
	pushResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pushResponse, nil
}

// Summary:
//	Helper function to check on the accept/deny status of a push to accept.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] refId: the reference id returned by the auth end point when the type is push_accept
//	[Required] timeout: the amount of time (in seconds) the check should run before failing.
//	[Required] interval: the frequency (in seconds) in which the api call to check the push status will run.
// 		   Recommended not to go lower than 5 (seconds)

func (r *Request) CheckPushAcceptStatus(c *sa.Client, refId string, timeout int, interval int)(*Response, error) {
	tout := time.After(time.Duration(timeout) * time.Second)
	tick := time.Tick(time.Duration(interval) * time.Second)
	for {
		select {
		case <- tout:
			return nil, errors.New("Request expired before response.")
		case <- tick:
			checkResponse, err := r.Get(c, refId)
			if err!= nil {
				return nil, err
			}
			switch checkResponse.Message {
			case "ACCEPTED", "DENIED", "FAILED", "EXPIRED":
				return checkResponse, nil
			case "PENDING":
				continue
			}
		}

	}
}

// Summary:
//	Helper function to send otp to a help_desk agent via the auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the userId of the user requesting the help_desk method.
//	[Required] factorId: from factor_id of the user endpoint, the help_desk option.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.

func (r *Request) SendHelpDesk(c *sa.Client, userId string, factorId string)(*Response, error){
	r.UserId = userId
	r.ReqType = "help_desk"
	r.FactorId = factorId
	helpResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return helpResponse, nil
}

// Summary:
//	non-exportable helper to build the endpoint api path with refid injected.

func buildEndpointPath(refId string) string {
	var buffer bytes.Buffer
	buffer.WriteString(endpoint)
	buffer.WriteString("/")
	buffer.WriteString(refId)
	return buffer.String()
}