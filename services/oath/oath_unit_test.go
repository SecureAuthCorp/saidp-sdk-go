package oath

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

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
	uAppID  = "12345"
	uAppKey = "12345"
	uHost   = "idp.host.com"
	uRealm  = "secureauth1"
	uPort   = 443
	uUser   = "user"
	uPass   = "password"
	uOtp    = "12345"
	uID     = "12345"
)

// TestOathSettingRequest tests the retrieval of oath settings.
func TestOathSettingRequest_Unit(t *testing.T) {
	defer gock.Off()
	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, generateOath(), n.String()),
	}

	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").Post("/secureauth1/api/v1/oath").Reply(200).BodyString(generateOath()).SetHeaders(headers)

	oathRequest := new(Request)
	oathResponse, err := oathRequest.GetOATHSettings(client, uUser, uPass, uOtp, uID)
	if err != nil {
		t.Error(err)
	}
	if oathResponse.Key != "12345" {
		t.Error("Failed to retrieve oath seed.")
	}
	valid, err := oathResponse.IsSignatureValid(client)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("Response signature is invalid")
	}
}

// generateOath generates a sample oath response for testing.
func generateOath() string {
	response := &Response{
		ServerTime:    "2017-03-20T15:54:59",
		Key:           "12345",
		Interval:      "60",
		Length:        "5",
		Offset:        "1",
		PinControl:    "foo",
		FailedWipe:    "foo",
		ScreenTimeout: "foo",
	}
	bytes, err := json.Marshal(response)
	if err != nil {
		fmt.Println(err)
	}
	return string(bytes)
}

func makeResponseSignature(c *sa.Client, r string, t string) string {
	var buffer bytes.Buffer
	buffer.WriteString(t)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(r)
	raw := buffer.String()
	byteKey, _ := hex.DecodeString(c.AppKey)
	byteData := []byte(raw)
	sig := hmac.New(sha256.New, byteKey)
	sig.Write([]byte(byteData))
	return base64.StdEncoding.EncodeToString(sig.Sum(nil))
}
