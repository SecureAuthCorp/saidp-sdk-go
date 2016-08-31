package groups


import (
	sa "github.com/SecureAuthCorp/saidp-sdk-go"
	"testing"
	"fmt"
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
	user1 = "user1"
	user2 = "user2"
	user3 = "user3"
	user4 = "user4"
	group1 = "group1"
	group2 = "group2"
	group3 = "group3"
	group4 = "group4"
	spacedGroup = "group 5"
)

func TestGroupRequest(t *testing.T) {
	client, err := sa.NewClient(appId, appKey, host, port, realm, true, false)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	// Test Single User to Single Group
	susgRequest := new(Request)
	susgResponse, err := susgRequest.AddUserToGroup(client, user1, spacedGroup)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Add Single User to Single Group Response: ")
	fmt.Println(susgResponse)

	// Test Single User to Multiple Groups
	sumgRequest := new(Request)
	sumgGroups := []string{group2,group3,group4}
	sumgResponse, err := sumgRequest.AddUserToGroups(client, user1, sumgGroups)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Add Single User to Multiple Groups Response: ")
	fmt.Println(sumgResponse)

	// Test Single Group to Single User
	sgsuRequest := new(Request)
	sgsuResponse, err := sgsuRequest.AddGroupToUser(client, group4, user1)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Add Single Group to Single User Response: ")
	fmt.Println(sgsuResponse)

	// Test Single Group to Multiple Users.
	sgmuRequest := new(Request)
	sgmuUsers := []string{user2,user3,user4}
	sgmuResponse, err := sgmuRequest.AddGroupToUsers(client, group2, sgmuUsers)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Add Single Group to Multiple Users Response: ")
	fmt.Println(sgmuResponse)
}