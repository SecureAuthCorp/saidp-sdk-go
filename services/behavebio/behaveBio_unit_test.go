package behavebio

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
	uAppID         = "12345"
	uAppKey        = "12345"
	uHost          = "idp.host.com"
	uRealm         = "secureauth1"
	uPort          = 443
	uBehaveProfile = ""
	uUserAgent     = ""
	uUser          = "user"
)

func TestBehaveBio_Unit(t *testing.T) {
	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	behaveJSTest, err := behaveBioJS(client)
	if err != nil {
		t.Error(err)
	}
	if !behaveJSTest {
		t.Error("Behave Bio JS test failed")
	}

	behavePostTest, err := behaveBioPost(client)
	if err != nil {
		t.Error(err)
	}
	if !behavePostTest {
		t.Error("Behave Bio Post test failed")
	}

	behavePutTest, err := behaveBioPut(client)
	if err != nil {
		t.Error(err)
	}
	if !behavePutTest {
		t.Error("Behave Bio Put test failed")
	}
}

func behaveBioJS(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "",
		Message: "",
		Source:  "https://SecureAuthIdPFQDN/SecureAuthIdPRealm/assets/scripts/api/behaveBio.obf.js?ver=9.0.0.22",
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

	gock.New("https://idp.host.com:443").
		Get("/secureauth1/api/v1/behavebio/js").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	behaveRequest := new(Request)
	behaveResponse, err := behaveRequest.GetBehaveJs(client)
	if err != nil {
		return false, err
	}
	valid, err := behaveResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func behaveBioPost(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "",
		BehaviorResults: BehaviorBioResults{
			TotalScore:      0.5,
			TotalConfidence: 0,
			Device:          "Desktop",
			Results:         []Results{},
		},
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

	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/behavebio").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	behaveRequest := new(Request)
	behaveResponse, err := behaveRequest.PostBehaveProfile(client, uUser, uBehaveProfile, "127.0.0.1", uUserAgent)
	if err != nil {
		return false, err
	}
	valid, err := behaveResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func behaveBioPut(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "valid",
		Message: "Reset sent to data store",
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

	gock.New("https://idp.host.com:443").
		Put("/secureauth1/api/v1/behavebio").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	behaveRequest := new(Request)
	behaveResponse, err := behaveRequest.ResetBehaveProfile(client, uUser, "ALL", "ALL", "ALL")
	if err != nil {
		return false, err
	}
	valid, err := behaveResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
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
