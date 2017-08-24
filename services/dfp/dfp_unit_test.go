package dfp

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
	uAppID           = "12345"
	uAppKey          = "12345"
	uHost            = "idp.host.com"
	uRealm           = "secureauth1"
	uPort            = 443
	uUser            = "user"
	uHostAddr        = "192.168.0.1"
	uFingerprintID   = "123456"
	uFingerprintJSON = `{"fingerprint":{"uaBrowser":{"name":"Chrome","version":"59.0.3071.115","major":"59"},"uaString":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36","uaDevice":{"model":null,"type":null,"vendor":null},"uaEngine":{"name":"WebKit","version":"537.36"},"uaOS":{"name":"Mac OS","version":"10.12.6"},"uaCPU":{"architecture":null},"uaPlatform":"MacIntel","language":"en-US","colorDepth":24,"pixelRatio":1,"screenResolution":"1920x1080","availableScreenResolution":"1920x1057","timezone":"America/Los_Angeles","timezoneOffset":420,"localStorage":true,"sessionStorage":true,"indexedDb":true,"addBehavior":false,"openDatabase":true,"cpuClass":null,"platform":"MacIntel","doNotTrack":null,"plugins":"application/pdf::pdf,Widevine Content Decryption Module.application/x-ppapi-widevine-cdm,Native Client Executable.application/x-nacl,Portable Document Format.application/x-google-chrome-pdf::pdf","canvas":"-414527139","webGl":"-1928487793","adBlock":false,"userTamperLanguage":false,"userTamperScreenResolution":false,"userTamperOS":false,"userTamperBrowser":false,"touchSupport":{"maxTouchPoints":0,"touchEvent":false,"touchStart":false},"cookieSupport":true,"fonts":"American Typewriter,Andale Mono,Apple Chancery,Apple Color Emoji,Apple SD Gothic Neo,Arial,Arial Black,Arial Hebrew,Arial Narrow,Arial Rounded MT Bold,Arial Unicode MS,AVENIR,Ayuthaya,Bangla Sangam MN,Baskerville,Bauhaus 93,Big Caslon,Bodoni 72,Bodoni 72 Oldstyle,Bodoni 72 Smallcaps,Bookshelf Symbol 7,Bradley Hand,Brush Script MT,Chalkboard,Chalkboard SE,Chalkduster,Cochin,Comic Sans MS,Copperplate,Courier New,Devanagari Sangam MN,Didot,English 111 Vivace BT,Euphemia UCAS,Futura,Geeza Pro,Geneva,Georgia,GeoSlab 703 Lt BT,GeoSlab 703 XBd BT,Gill Sans,Gujarati Sangam MN,Gurmukhi MN,Heiti SC,Heiti TC,Helvetica,Helvetica Neue,Hiragino Kaku Gothic ProN,Hiragino Mincho ProN,Hoefler Text,Humanst 521 Cn BT,Impact,Kailasa,Kannada Sangam MN,Krungthep,LUCIDA GRANDE,Malayalam Sangam MN,Marion,Marker Felt,Microsoft Sans Serif,Modern No. 20,Monaco,Nadeem,Noteworthy,OPTIMA,Oriya Sangam MN,Palatino,Papyrus,Plantagenet Cherokee,Savoye LET,Sinhala Sangam MN,Skia,Snell Roundhand,Tahoma,Tamil Sangam MN,Telugu Sangam MN,Thonburi,Times,Times New Roman,Trebuchet MS,Univers CE 55 Medium,Verdana,Wingdings,Wingdings 2,Wingdings 3,Zapfino"}}`
)

func TestDFP_Unit(t *testing.T) {
	client, err := sa.NewClient(uAppID, uAppKey, uHost, uPort, uRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	dfpJSTest, err := dfpJS(client)
	if err != nil {
		t.Error(err)
	}
	if !dfpJSTest {
		t.Error("DFP JS test failed")
	}

	validateTest, err := validate(client)
	if err != nil {
		t.Error(err)
	}
	if !validateTest {
		t.Error("Validate DFP test failed")
	}

	confirmTest, err := confirm(client)
	if err != nil {
		t.Error(err)
	}
	if !confirmTest {
		t.Error("Confirm DFP test failed")
	}

	scoreTest, err := score(client)
	if err != nil {
		t.Error(err)
	}
	if !scoreTest {
		t.Error("Score DFP test failed")
	}

	saveTest, err := save(client)
	if err != nil {
		t.Error(err)
	}
	if !saveTest {
		t.Error("Save DFP test failed")
	}
}

func dfpJS(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:  "",
		Message: "",
		Source:  `https://SecureAuthIdPFQDN/SecureAuthIdPRealm/assets/scripts/api/secureauth-api.js?ver=8.1.1.071`,
	}
	bytes, err := json.Marshal(responseMock)
	if err != nil {
		return false, err
	}
	responseMockJSON := string(bytes)
	n := time.Now()
	headers := map[string]string{
		"X-SA-DATE":      n.String(),
		"X-SA-SIGNATURE": makeResponseSignature(client, responseMockJSON, n.String()),
	}

	gock.New("https://idp.host.com:443").
		Get("/secureauth1/api/v1/dfp/js").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	dfpJSRequest := new(Request)
	dfpJSResponse, err := dfpJSRequest.GetDfpJs(client)
	if err != nil {
		return false, err
	}
	valid, err := dfpJSResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func validate(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:          "not_found",
		Message:         "",
		FingerprintID:   "12345654321",
		FingerprintName: "Windows 7 - Firefox 41.0",
		Score:           "0.00",
		MatchScore:      "95.00",
		UpdateScore:     "80.00",
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
		Post("/secureauth1/api/v1/dfp/validate").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ValidateDfp(client, uUser, uHostAddr, uFingerprintID, uFingerprintJSON)
	if err != nil {
		return false, err
	}
	valid, err := dfpResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func confirm(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:          "verified",
		Message:         "Fingerprint has been confirmed.",
		UserID:          uUser,
		FingerprintID:   uFingerprintID,
		FingerprintName: "Windows 7 - Firefox 41.0",
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
		Post("/secureauth1/api/v1/dfp/confirm").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ConfirmDfp(client, uUser, uFingerprintID)
	if err != nil {
		return false, err
	}
	valid, err := dfpResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func score(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:          "not_found",
		Message:         "",
		FingerprintID:   "12345654321",
		FingerprintName: "Windows 7 - Firefox 41.0",
		Score:           "0.00",
		MatchScore:      "95.00",
		UpdateScore:     "80.00",
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
		Post("/secureauth1/api/v1/dfp/score").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ScoreDfp(client, uUser, uHostAddr, uFingerprintID, uFingerprintJSON)
	if err != nil {
		return false, err
	}
	valid, err := dfpResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func save(client *sa.Client) (bool, error) {
	defer gock.Off()

	responseMock := &Response{
		Status:          "verified",
		Message:         "Fingerprint has been confirmed.",
		UserID:          uUser,
		FingerprintID:   uFingerprintID,
		FingerprintName: "Windows 7 - Firefox 41.0",
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
		Post("/secureauth1/api/v1/dfp/save").
		Reply(200).BodyString(responseMockJSON).
		SetHeaders(headers)

	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.SaveDfp(client, uUser, uHostAddr, uFingerprintID, uFingerprintJSON)
	if err != nil {
		return false, err
	}
	valid, err := dfpResponse.IsSignatureValid(client)
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
