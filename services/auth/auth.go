package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	sa "github.com/secureauthcorp/saidp-sdk-go"
	validators "github.com/secureauthcorp/saidp-sdk-go/utilities/validators"
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

const endpoint = "/api/v1/auth"

var typeList = []string{"call", "sms", "email"}

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	RefID        string         `json:"reference_id,omitempty"`
	Status       string         `json:"status,omitempty"`
	Message      string         `json:"message,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	OTP          string         `json:"otp,omitempty"`
	HTTPResponse *http.Response `json:"-"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to submit access history for.
//	[Required] ReqType: type of auth request, valid entries: user_id, password, kba, oath,
// 		   pin, call, sms, email, push, push_accept, help_desk
//	Token: used to pass data for validation
//	[Required] FactorID: identifier to which attribute in the users profile the request type
// 		   should use. Also referred to as device id.
//	PushDetails: if ReqType is push_accept, push details will allow details of the auth attempt
//		   to be sent with the push request.
//	EvaluateNum: if true, number profile evaluation will be performed. Only applicable for call
//		   and sms auth request types
type Request struct {
	UserID      string             `json:"user_id"`
	ReqType     string             `json:"type"`
	Token       string             `json:"token,omitempty"`
	FactorID    string             `json:"factor_id,omitempty"`
	PushDetails *PushAcceptDetails `json:"push_accept_details,omitempty"`
	EvaluateNum bool               `json:"evaluate_number,omitempty"`
}

// PushAcceptDetails :
//	Details for the push_accept request.
// Fields:
//	CompanyName: Displayed on the push to accept request.
//	AppDesc: Displayed on the push to accept request.
//	EnduserIP: Displayed on the push to accept request.
type PushAcceptDetails struct {
	CompanyName string `json:"company_name"`
	AppDesc     string `json:"application_description"`
	EnduserIP   string `json:"enduser_ip"`
}

// Post :
//	Executes a post to the auth endpoint.
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
	authResponse := new(Response)
	if err := json.NewDecoder(httpResponse.Body).Decode(authResponse); err != nil {
		return nil, err
	}
	authResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return authResponse, nil
}

// Get :
//	Executes a get request for checking push to accept status.
// Parameters:
//	[Required] r: empty struct used to make Get easy.
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Get(c *sa.Client, refID string) (*Response, error) {
	endpoint := buildEndpointPath(refID)
	httpRequest, err := c.BuildGetRequest(endpoint)
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
	authResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return authResponse, nil
}

// ValidateUser :
//	Helper function for making Validate User auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateUser(c *sa.Client, userID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "user_id"
	validateResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return validateResponse, nil
}

// ValidatePassword :
//	Helper function for making Validate Password auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] password: the password of the user you wish to validate.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidatePassword(c *sa.Client, userID string, password string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "password"
	r.Token = password
	passwordResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return passwordResponse, nil
}

// ValidateKba :
//	Helper function for making Validate Kba auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] answer: the answer for the kbq value you want to validate.
//	[Required] kbqId: the id of the kbq the answer will be validated against.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateKba(c *sa.Client, userID string, answer string, kbqID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "kba"
	r.Token = answer
	r.FactorID = kbqID
	kbaResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return kbaResponse, nil
}

// ValidateOath :
//	Helper function for making Validate Oath auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] oathOtp: the otp value to be validated.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier to which Oath is registered to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidateOath(c *sa.Client, userID string, oathOTP string, deviceID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "oath"
	r.Token = oathOTP
	r.FactorID = deviceID
	oathResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return oathResponse, nil
}

// ValidatePin :
//	Helper function for making Validate Pin auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] pin: the pin to be validated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) ValidatePin(c *sa.Client, userID string, pin string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "pin"
	r.Token = pin
	pinResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pinResponse, nil
}

// SendOtpAdHoc :
//	Helper function for making ad-hoc otp deliveries to phone numbers or email address not in the backing datastore.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user you wish to validate.
//	[Required] token: the number or email address the OTP will be delivered to.
//	[Required] reqType: the type of delivery method to be used. Only call, sms, or email are valid.
//	[Required] eval: if true, perform number profile evaluation against the provided token. Only valid for call and sms reqTypes.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendOtpAdHoc(c *sa.Client, userID string, token string, reqType string, eval bool) (*Response, error) {
	if !validators.ValidateRequestType(reqType) {
		return nil, errors.New("Not a valid type, valid types: call, sms, or email")
	}
	if (eval) && (reqType == "email") {
		return nil, errors.New("Number evaluation can only be used with call or sms reqTypes")
	}
	r.UserID = userID
	r.ReqType = reqType
	r.Token = token
	r.EvaluateNum = eval
	adHocResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return adHocResponse, nil
}

// SendCallOtp :
//	Helper function to send otp via phone call through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the call will be sent to.
//	[Required] factorID: from factor_id of a user endpoint call. Identifier of the profile
//		   attribute that the call should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendCallOtp(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "call"
	r.FactorID = factorID
	callResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return callResponse, nil
}

// SendCallOtpWithEval :
//	Helper function to send otp via phone call with number profile evaluation through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the call will be sent to.
//	[Required] factorID: from factor_id of a user endpoint call. Identifier of the profile
//		   attribute that the call should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendCallOtpWithEval(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "call"
	r.FactorID = factorID
	r.EvaluateNum = true
	callResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return callResponse, nil
}

// SendSMSOtp :
//	Helper function to send otp via sms through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the sms will be sent to.
//	[Required] factorID: from factor_id of a user endpoint sms. Identifier of the profile
//		   attribute that the sms should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendSMSOtp(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "sms"
	r.FactorID = factorID
	smsResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return smsResponse, nil
}

// SendSMSOtpWithEval :
//	Helper function to send otp via sms with number profile evaluation through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the sms will be sent to.
//	[Required] factorID: from factor_id of a user endpoint sms. Identifier of the profile
//		   attribute that the sms should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendSMSOtpWithEval(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "sms"
	r.FactorID = factorID
	r.EvaluateNum = true
	smsResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return smsResponse, nil
}

// SendEmailOtp :
//	Helper function to send otp via email through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the email will be sent to.
//	[Required] factorID: from factor_id of a user endpoint email. Identifier of the profile
//		   attribute that the email should be sent to.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendEmailOtp(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "email"
	r.FactorID = factorID
	emailResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return emailResponse, nil
}

// SendPushNotify :
//	Helper function to send otp via push notification through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the push notification will be sent to.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier which is registered.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendPushNotify(c *sa.Client, userID string, deviceID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "push"
	r.FactorID = deviceID
	pushResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pushResponse, nil
}

// SendPushAccept :
//	Helper function to send otp via push notification through auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user the push to accept will be sent to.
//	[Required] deviceId: from factor_id of the user endpoint, the device identifier which is registered.
//	companyName: Displayed on the push to accept request.
//	appDesc: Displayed on the push to accept request.
//	userIp: Displayed on the push to accept request.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendPushAccept(c *sa.Client, userID string, deviceID string, companyName string, appDesc string, userIP string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "push_accept"
	r.FactorID = deviceID
	pushDetails := new(PushAcceptDetails)
	pushDetails.CompanyName = companyName
	pushDetails.AppDesc = appDesc
	pushDetails.EnduserIP = userIP
	r.PushDetails = pushDetails
	pushResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return pushResponse, nil
}

// CheckPushAcceptStatus :
//	Helper function to check on the accept/deny status of a push to accept.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] refId: the reference id returned by the auth end point when the type is push_accept
//	[Required] timeout: the amount of time (in seconds) the check should run before failing.
//	[Required] interval: the frequency (in seconds) in which the api call to check the push status will run.
// 		   Recommended not to go lower than 5 (seconds)
func (r *Request) CheckPushAcceptStatus(c *sa.Client, refID string, timeout int, interval int) (*Response, error) {
	tout := time.After(time.Duration(timeout) * time.Second)
	tick := time.Tick(time.Duration(interval) * time.Second)
	for {
		select {
		case <-tout:
			return nil, errors.New("Request expired before response")
		case <-tick:
			checkResponse, err := r.Get(c, refID)
			if err != nil {
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

// SendHelpDesk :
//	Helper function to send otp to a help_desk agent via the auth endpoint posts.
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userID: the userID of the user requesting the help_desk method.
//	[Required] factorID: from factor_id of the user endpoint, the help_desk option.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) SendHelpDesk(c *sa.Client, userID string, factorID string) (*Response, error) {
	r.UserID = userID
	r.ReqType = "help_desk"
	r.FactorID = factorID
	helpResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return helpResponse, nil
}

// buildEndpointPath :
//	non-exportable helper to build the endpoint api path with refid injected.
func buildEndpointPath(refID string) string {
	var buffer bytes.Buffer
	buffer.WriteString(endpoint)
	buffer.WriteString("/")
	buffer.WriteString(refID)
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
