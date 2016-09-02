package behavebio

import (
	"testing"
	"fmt"
	sa "github.com/secureauthcorp/saidp-sdk-go"
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
	behaveProfile = ``
	userAgent = ``
	user = "user"
)

func TestBehaveBioRequest (t *testing.T) {
	client, err := sa.NewClient(appId, appKey, host, port, realm, true, false)
	if err != nil {
		fmt.Println(err)
	}
	behaveRequest := new(Request)
	getSrcResponse, err := behaveRequest.GetBehaveJs(client)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Javascript Source Response:")
	fmt.Println(getSrcResponse)
	postBehaveResp, err := behaveRequest.PostBehaveProfile(client, user, behaveProfile, "192.168.0.1", userAgent)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Post Behavior Profile Response: ")
	fmt.Println(postBehaveResp)
	resetBehaveResp, err := behaveRequest.ResetBehaveProfile(client, user, "ALL", "ALL", "ALL")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Reset Behavior Profile Response:")
	fmt.Println(resetBehaveResp)
}