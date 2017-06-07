package otp

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/h2non/gock"
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

const (
	appID  = "12345"
	appKey = "12345"
	host   = "idp.host.com"
	realm  = "secureauth1"
	port   = 443
	user   = "user"
	domain = "domain"
	otp    = "123456"
)

// TestOtpValidateRequest tests the validation of an otp
func TestOtpValidateRequest(t *testing.T) {
	defer gock.Off()
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").Post("/secureauth1/api/v1/otp/validate").Reply(200).BodyString(generateOTP())

	client, err := sa.NewClient(appID, appKey, host, port, realm, true, false)
	if err != nil {
		t.Error(err)
	}
	otpRequest := new(Request)
	otpResponse, err := otpRequest.ValidateOTP(client, user, domain, otp)
	if err != nil {
		t.Error(err)
	}
	if otpResponse.Status != "valid" {
		t.Error("failed to validate otp")
	}
}

// generateOTP generates a sample otp response for testing.
func generateOTP() string {
	response := &Response{
		Status:       "valid",
		Message:      "",
		UserID:       user,
		HTTPResponse: nil,
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		fmt.Println(err)
	}
	return string(bytes)
}
