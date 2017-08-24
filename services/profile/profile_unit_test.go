package profile

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
)

func TestProfile_Unit(t *testing.T) {
	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	getTest, err := getProfile(client)
	if err != nil {
		t.Error(err)
	}
	if !getTest {
		t.Error("Get User Profile test failed")
	}

	createTest, err := createUser(client)
	if err != nil {
		t.Error(err)
	}
	if !createTest {
		t.Error("Create User test failed")
	}

	updateTest, err := updateProfile(client)
	if err != nil {
		t.Error(err)
	}
	if !updateTest {
		t.Error("Update Profile test failed")
	}

}

func getProfile(client *sa.Client) (bool, error) {
	defer gock.Off()

	profileJSON := `{"userId":"jdoe","properties":{"firstName":{"value":"John","isWritable":"true"},"lastName":{"value":"Doe","isWritable":"true"},"phone1":{"value":"123-456-7890","isWritable":"true"},"phone2":{"value":"234-567-8910","isWritable":"true"},"email1":{"value":"jdoe@dev.local","isWritable":"true"},"email2":{"value":"jdoe@gmail.com","isWritable":"true"},"pinHash":{"value":"1234","isWritable":"true"},"auxId1":{"value":"123 Anywhere Drive","isWritable":"true"},"auxId2":{"value":"Suite #100","isWritable":"true"},"ExtProperty1":{"displayName":"New Property","value":"John","isWritable":"false"}},"knowledgeBase":{"kbq1":{"question":"What is your favorite color?","answer":"red"},"kbq2":{"question":"What was your favorite childhood game?","answer":"hide and seek"},"helpDeskKb":{"question":"What city were you born in?","answer":"Alexandria"}},"groups":["CN=SharePoint Developers,OU=jdoe,DC=dev,DC=local","CN=SharePoint RnD,OU=jdoe,DC=admin,DC=local"],"accessHistories":[{"userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4)","ipAddress":"192.168.1.2","timeStamp":"2016-04-12T22:14:19.928868Z","authState":"Success"}],"status":"found","message":""}`
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, profileJSON, n.String()),
	}

	gock.New("https://idp.host.com:443").
		Get("/secureauth1/api/v1/users/" + uUser).
		Reply(200).BodyString(profileJSON).
		SetHeaders(headers)

	profileRequest := new(Request)
	profileResponse, err := profileRequest.Get(client, uUser)
	if err != nil {
		return false, err
	}
	valid, err := profileResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func createUser(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "success",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, string(bytes), n.String()),
	}

	gock.New("https://idp.host.com:443").
		Post("/secureauth1/api/v1/users").
		Reply(200).BodyString(string(bytes)).
		SetHeaders(headers)

	profileRequest := &Request{
		UserID:   "jdoe",
		Password: "Password1",
		Props: &PropertiesRequest{
			FirstName: "John",
			LastName:  "Doe",
			Phone1:    "555-555-5555",
			Email1:    "jdoe@secureauth.com",
		},
		KnowledgeBase: &KnowledgeBase{
			Kbq1: &KnowledgeBaseData{
				Question: "What is your favorite color?",
				Answer:   "red",
			},
		},
	}
	profileResponse, err := profileRequest.CreateUser(client)
	if err != nil {
		return false, err
	}
	valid, err := profileResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func updateProfile(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "success",
		Message: "",
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		fmt.Println(err)
	}
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, string(bytes), n.String()),
	}

	gock.New("https://idp.host.com:443").
		Put("/secureauth1/api/v1/users/" + uUser).
		Reply(200).BodyString(string(bytes)).
		SetHeaders(headers)

	profileRequest := &Request{
		Props: &PropertiesRequest{
			FirstName: "John",
			LastName:  "Doe",
			Phone1:    "555-555-5555",
			Email1:    "jdoe@secureauth.com",
		},
		KnowledgeBase: &KnowledgeBase{
			Kbq1: &KnowledgeBaseData{
				Question: "What is your favorite color?",
				Answer:   "red",
			},
		},
	}

	profileResponse, err := profileRequest.Put(client, uUser)
	if err != nil {
		return false, err
	}
	valid, err := profileResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
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
