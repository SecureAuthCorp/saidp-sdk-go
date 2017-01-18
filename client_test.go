package saidp_sdk_go

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/secureauthcorp/saidp-sdk-go/services/factors"
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
	appID  = ""
	appKey = ""
	host   = "host.company.com"
	realm  = "secureauth1"
	port   = 443
	user   = "user"
)

func TestClient(t *testing.T) {
	client, err := NewClient(appID, appKey, host, port, realm, true, false)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Client Created :")
	fmt.Println(client)
	getRequest, err := client.BuildGetRequest("/api/v1/users/" + user + "/factors")
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Get Request Built :")
	fmt.Println(getRequest)
	postRequest, err := client.BuildPostRequest("/api/v1/auth", "Content")
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Post Request Built :")
	fmt.Println(postRequest)
	putRequest, err := client.BuildPutRequest("/api/v1/auth", "Content")
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Put Request Built: ")
	fmt.Println(putRequest)
	doResponse, err := client.Do(getRequest)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Client Do HTTP Response: ")
	fmt.Println(doResponse)
	fmt.Println("Unmarshaled HTTP Response to Factors Response: ")
	factorResponse := new(factors.Response)
	if err := json.NewDecoder(doResponse.Body).Decode(factorResponse); err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	factorResponse.HTTPResponse = doResponse
	doResponse.Body.Close()
	fmt.Println(factorResponse)
}
