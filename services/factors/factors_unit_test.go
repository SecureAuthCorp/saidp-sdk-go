package factors

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
	uAppID  = "12345"
	uAppKey = "12345"
	uHost   = "idp.host.com"
	uRealm  = "secureauth1"
	uPort   = 443
	uUser   = "user"
)

func TestFactors_Unit(t *testing.T) {
	defer gock.Off()

	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, generateResponse(), n.String()),
	}
	// Set up a test responder for the api.
	gock.New("https://idp.host.com:443").
		Get("/secureauth1/api/v1/users/" + uUser + "/factors").
		Reply(200).
		BodyString(generateResponse()).
		SetHeaders(headers)

	factorRequest := new(Request)
	factorResponse, err := factorRequest.Get(client, uUser)
	if err != nil {
		t.Error(err)
	}
	valid, err := factorResponse.IsSignatureValid(client)
	if err != nil {
		t.Error(err)
	}
	if !valid {
		t.Error("Response signature is invalid")
	}
}

func generateResponse() string {
	var jsonFactors = `{"status":"found","message":"","user_id":"jsmith","factors":[{"type":"phone","id":"Phone1","value":"123-456-7890","capabilities":["call"]},{"type":"phone","id":"Phone2","value":"987-654-3210","capabilities":["sms","call"]},{"type":"email","id":"Email1","value":"jsmith@company.com"},{"type":"kbq","id":"KBQ1","value":"What city were you born in?"},{"type":"kbq","id":"KBQ2","value":"What was your favorite childhood game?"},{"type":"kbq","id":"KBQ3","value":"What was your dream job as a child?"},{"type":"kbq","id":"KBQ4","value":"Who is your personal hero?"},{"type":"kbq","id":"KBQ5","value":"What is the last name of your favorite school teacher?"},{"type":"kbq","id":"KBQ6","value":"What is the name of your favorite childhood pet?"},{"type":"help_desk","id":"HelpDesk1","value":"987-654-3210"},{"type":"help_desk","id":"HelpDesk2","value":"987-654-3211"},{"type":"push","id":"8117b62897734d71b48ecdcab19bd437","value":"HTC One","capabilities":["push","push_accept"]},{"type":"oath","id":"63c6b390cac04efb8d283828ed29c120","value":"SecureAuth OTP Mobile App"},{"type":"pin","value":"Private PIN"}]}`
	response := new(Response)
	if err := json.Unmarshal([]byte(jsonFactors), &response); err != nil {
		return ""
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
