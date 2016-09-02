package profile

import (
	"testing"
	sa "github.com/secureauthcorp/saidp-sdk-go"
	"fmt"
	"strings"
)

/*
**********************************************************************
*   @author jhickman@secureauth.com
*
*  Copyright (c) 2016, SecureAuth
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
	appId = ""
	appKey = ""
	host = "host.company.com"
	realm = "secureauth1"
	port = 443
	user = "user"
)

func TestProfileRequest(t *testing.T ){
	client, err := sa.NewClient(appId, appKey, host, port, realm, true, false)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	profileRequest := new(Request)
	profileResponse, err := profileRequest.Get(client, user)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Get Profile Response: ")
	fmt.Println(profileResponse)
	if strings.Contains(profileResponse.Status, "not_found") {
		postRequest := new(Request)
		postRequest.UserId = user
		postRequest.Password = "password"
		props := new(PropertiesRequest)
		props.FirstName = "Jim"
		props.LastName = "Beam"
		props.Phone1 = "5555555555"
		props.Email1 = "someone@noreply.com"
		props.AuxId1 = "TestAuxID1Data"
		postRequest.Props = props
		kbq := new(KnowledgeBase)
		kbq1 := new(KnowledgeBaseData)
		kbq1.Question = "What was the make of your first car."
		kbq1.Answer = "car"
		kbq.Kbq1 = kbq1
		postRequest.KnowledgeBase = kbq
		postResponse, err := postRequest.CreateUser(client)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
		fmt.Println("Post Profile Response: ")
		fmt.Println(postResponse)
	} else {
		putRequest := new(Request)
		putProps := new(PropertiesRequest)
		putProps.AuxId2 = "UpdateAuxId2"
		putKbq := new(KnowledgeBase)
		putKbq1 := new(KnowledgeBaseData)
		putKbq1.Question = "Who was your favorit teacher?"
		putKbq1.Answer = "teacher"
		putKbq.Kbq2 = putKbq1
		putRequest.Props = putProps
		putRequest.KnowledgeBase = putKbq
		putResponse, err := putRequest.Put(client, user)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
		fmt.Println("Put Profile Response: ")
		fmt.Println(putResponse)
	}
}