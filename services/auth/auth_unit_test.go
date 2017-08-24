package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/h2non/gock"
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
	uAppID       = "12345"
	uAppKey      = "12345"
	uHost        = "idp.host.com"
	uRealm       = "secureauth1"
	uPort        = 443
	uUser        = "user"
	uUserIP      = "192.168.0.1"
	uPassword    = "Password1"
	uKba         = "HighSchool,Teacher,Honda"
	uOathDevice  = "1234512315123123514523145"
	uPushDevice  = "14982456718247561298123984"
	uPhoneNumber = "5555555555"
	uEmail       = "test@test.com"
)

// TestAuth_Unit tests the submitting of an Auth request. This is a unit test.
func TestAuth_Unit(t *testing.T) {
	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	validUserTest, err := validateUser(client)
	if err != nil {
		t.Error(err)
	}
	if !validUserTest {
		t.Error("Validate User test failed")
	}

	validatePasswordTest, err := validatePassword(client)
	if err != nil {
		t.Error(err)
	}
	if !validatePasswordTest {
		t.Error("Validate Password test failed")
	}

	validateKbaTest, err := validateKba(client)
	if err != nil {
		t.Error(err)
	}
	if !validateKbaTest {
		t.Error("Validate KBA test failed")
	}

	validateOathTest, err := validateOath(client)
	if err != nil {
		t.Error(err)
	}
	if !validateOathTest {
		t.Error("Validate Oath test failed")
	}

	validatePinTest, err := validatePin(client)
	if err != nil {
		t.Error(err)
	}
	if !validatePinTest {
		t.Error("Validate PIN test failed")
	}

	sendCallOTPTest, err := sendCallOtp(client)
	if err != nil {
		t.Error(err)
	}
	if !sendCallOTPTest {
		t.Error("Send Call OTP test failed")
	}

	sendSMSOTPTest, err := sendSMSOtp(client)
	if err != nil {
		t.Error(err)
	}
	if !sendSMSOTPTest {
		t.Error("Send SMS OTP test failed")
	}

	sendEmailOTPTest, err := sendEmailOtp(client)
	if err != nil {
		t.Error(err)
	}
	if !sendEmailOTPTest {
		t.Error("Send Email OTP test failed")
	}

	sendPushNotifyTest, err := sendPushNotify(client)
	if err != nil {
		t.Error(err)
	}
	if !sendPushNotifyTest {
		t.Error("Send Push Notify OTP test failed")
	}

	sendPushAcceptTest, err := sendPushAccept(client)
	if err != nil {
		t.Error(err)
	}
	if !sendPushAcceptTest {
		t.Error("Send Push Accept")
	}

	pushStatusTest, err := pushAcceptStatus(client)
	if err != nil {
		t.Error(err)
	}
	if !pushStatusTest {
		t.Error("Push Status Check test failed")
	}

	sendAdhocTest, err := sendAdhoc(client)
	if err != nil {
		t.Error(err)
	}
	if !sendAdhocTest {
		t.Error("Send Adhoc OTP test failed")
	}

	helpDeskTest, err := sendHelpDesk(client)
	if err != nil {
		t.Error(err)
	}
	if !helpDeskTest {
		t.Error("Send HelpDesk OTP test failed")
	}
}

func validateUser(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "found",
		Message: "User Id found",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.ValidateUser(client, uUser)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func validatePassword(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.ValidatePassword(client, uUser, uPassword)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func validateKba(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.ValidateKba(client, uUser, uKba, "KBQ1")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func validateOath(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.ValidateOath(client, uUser, "123456", uOathDevice)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func validatePin(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.ValidatePin(client, uUser, "123456")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func sendCallOtp(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendCallOtp(client, uUser, "Phone1")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func sendSMSOtp(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendSMSOtp(client, uUser, "Phone1")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func sendEmailOtp(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendEmailOtp(client, uUser, "Email1")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func sendPushNotify(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendPushNotify(client, uUser, uPushDevice)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain valid OTP")
	}
	return true, nil
}

func sendPushAccept(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		RefID:   "a7e855c1-45a3-XXXXXX",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendPushAccept(client, uUser, uPushDevice, "Test Company", "Test Desc", uUserIP)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func pushAcceptStatus(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "found",
		Message: "ACCEPTED",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Get("/secureauth1/api/v1/auth/a7e855c1-45a3-XXXXXX").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.CheckPushAcceptStatus(client, "a7e855c1-45a3-XXXXXX", 30, 5)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.Message != responseMock.Message {
		return false, errors.New("Response does not have the correct message")
	}
	return true, nil
}

func sendAdhoc(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}

	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}

	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendOtpAdHoc(client, uUser, uPhoneNumber, "sms", true)
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain a valid OTP")
	}
	return true, nil
}

func sendHelpDesk(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		UserID:  uUser,
		OTP:     "123456",
	}

	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}

	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/auth").
		Reply(200).
		BodyString(responseMockJSON).
		SetHeaders(headers)

	authRequest := new(Request)
	authResponse, err := authRequest.SendHelpDesk(client, uUser, "HelpDesk1")
	if err != nil {
		return false, err
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	if authResponse.OTP != responseMock.OTP {
		return false, errors.New("Response does not contain a valid OTP")
	}
	return true, nil
}

func makeResponseSignature(c *sa.Client, response string, timeStamp string) string {
	var buffer bytes.Buffer
	buffer.WriteString(timeStamp)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(response)
	raw := buffer.String()
	byteKey, _ := hex.DecodeString(c.AppKey)
	byteData := []byte(raw)
	sig := hmac.New(sha256.New, byteKey)
	sig.Write([]byte(byteData))
	return base64.StdEncoding.EncodeToString(sig.Sum(nil))
}
