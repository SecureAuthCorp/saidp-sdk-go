package auth

import (
	"errors"
	"testing"

	factors "github.com/jhickmansa/saidp-sdk-go/services/factors"
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
	fAppID       = ""
	fAppKey      = ""
	fHost        = ""
	fRealm       = ""
	fPort        = 443
	fUser        = ""
	fPass        = ""
	fKba         = ""
	fPhoneNumber = ""
	fOathOtp     = ""
	fPin         = ""
)

var (
	fFactors = new(factors.Response)
	fRefID   = ""
)

func TestAuthRequest(t *testing.T) {
	client, err := sa.NewClient(fAppID, fAppKey, fHost, fPort, fRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	userValidTest, err := userValidation(client)
	if err != nil {
		t.Error(err)
	}
	if !userValidTest {
		t.Error("Validate User test failed")
	}

	passValidTest, err := passwordValidation(client)
	if err != nil {
		t.Error(err)
	}
	if !passValidTest {
		t.Error("Validate password test failed")
	}

	if err := getFactors(client); err != nil {
		t.Error("Get User Factors failed")
	}

	for _, factor := range fFactors.Factors {
		switch factor.FactorType {
		case "kbq":
			kbaValidTest, err := kbaValidation(client)
			if err != nil {
				t.Error(err)
			}
			if !kbaValidTest {
				t.Error("Validate KBA test failed")
			}
		case "oath":
			oathValidTest, err := oathValidation(client)
			if err != nil {
				t.Error(err)
			}
			if !oathValidTest {
				t.Error("Validate OATH test failed")
			}
		case "pin":
			pinValidTest, err := pinValidation(client)
			if err != nil {
				t.Error(err)
			}
			if !pinValidTest {
				t.Error("Validate PIN test failed")
			}
		case "phone":
			callOtpTest, err := callOtp(client)
			if err != nil {
				t.Error(err)
			}
			if !callOtpTest {
				t.Error("Call OTP test failed")
			}

			smsOtpTest, err := smsOtp(client)
			if err != nil {
				t.Error(err)
			}
			if !smsOtpTest {
				t.Error("SMS OTP test failed")
			}
		case "email":
			emailOtpTest, err := emailOtp(client)
			if err != nil {
				t.Error(err)
			}
			if !emailOtpTest {
				t.Error("Email OTP test failed")
			}
		case "push":
			pushNotifyTest, err := pushNotify(client)
			if err != nil {
				t.Error(err)
			}
			if !pushNotifyTest {
				t.Error("Push Notification test failed")
			}

			pushAcceptTest, err := pushAccept(client)
			if err != nil {
				t.Error(err)
			}
			if !pushAcceptTest {
				t.Error("Push To Accept test failed")
			}

			checkPushTest, err := checkPushStatus(client)
			if err != nil {
				t.Error(err)
			}
			if !checkPushTest {
				t.Error("Check Push To Accept test failed")
			}
		case "help_desk":
			helpDeskTest, err := helpDesk(client)
			if err != nil {
				t.Error(err)
			}
			if !helpDeskTest {
				t.Error("HelpDesk OTP test failed")
			}
		}
	}
	adHocOtpTest, err := adHocOtp(client)
	if err != nil {
		t.Error(err)
	}
	if !adHocOtpTest {
		t.Error("AdHoc OTP test failed")
	}
}

func userValidation(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.ValidateUser(client, fUser)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func passwordValidation(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.ValidatePassword(client, fUser, fPass)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func getFactors(client *sa.Client) error {
	factorsRequest := new(factors.Request)
	factorResponse, err := factorsRequest.Get(client, fUser)
	if err != nil {
		return err
	}
	valid, err := factorResponse.IsSignatureValid(client)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("Response signature is invalid")
	}
	fFactors = factorResponse
	return nil
}

func kbaValidation(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.ValidateKba(client, fUser, fKba, "KBQ1")
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func oathValidation(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var oathID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "oath" {
			oathID = factor.ID
		}
	}
	authResponse, err := authRequest.ValidateOath(client, fUser, fOathOtp, oathID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func pinValidation(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.ValidatePin(client, fUser, fPin)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func callOtp(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var phoneID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "phone" {
			for _, capability := range factor.Capabilities {
				if capability == "call" {
					phoneID = factor.ID
				}
			}
		}
	}
	authResponse, err := authRequest.SendCallOtp(client, fUser, phoneID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func smsOtp(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var phoneID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "phone" {
			for _, capability := range factor.Capabilities {
				if capability == "sms" {
					phoneID = factor.ID
				}
			}
		}
	}
	authResponse, err := authRequest.SendSMSOtp(client, fUser, phoneID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func emailOtp(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var emailID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "email" {
			emailID = factor.ID
		}
	}
	authResponse, err := authRequest.SendEmailOtp(client, fUser, emailID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func adHocOtp(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.SendOtpAdHoc(client, fUser, fPhoneNumber, "sms", true)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func pushNotify(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var pushID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "push" {
			for _, capability := range factor.Capabilities {
				if capability == "push" {
					pushID = factor.ID
				}
			}
		}
	}
	authResponse, err := authRequest.SendPushNotify(client, fUser, pushID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func pushAccept(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var pushID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "push" {
			for _, capability := range factor.Capabilities {
				if capability == "push_accept" {
					pushID = factor.ID
				}
			}
		}
	}
	authResponse, err := authRequest.SendPushAccept(client, fUser, pushID, "SDK Test", "Push Accept Test", "127.0.0.1")
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
	}
	valid, err := authResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	fRefID = authResponse.RefID
	return true, nil
}

func checkPushStatus(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	authResponse, err := authRequest.CheckPushAcceptStatus(client, fRefID, 30, 5)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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

func helpDesk(client *sa.Client) (bool, error) {
	authRequest := new(Request)
	var helpDeskID = ""
	for _, factor := range fFactors.Factors {
		if factor.FactorType == "help_desk" {
			helpDeskID = factor.ID
		}
	}
	authResponse, err := authRequest.SendHelpDesk(client, fUser, helpDeskID)
	if err != nil {
		return false, err
	}
	if authResponse.Status == "server_error" {
		return false, errors.New("auth endpoint returned server error: " + authResponse.Message)
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
