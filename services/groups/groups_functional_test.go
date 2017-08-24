package groups

import (
	"errors"
	"testing"

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
	fAppID       = ""
	fAppKey      = ""
	fHost        = ""
	fRealm       = ""
	fPort        = 443
	fUser1       = "user1"
	fUser2       = "user2"
	fUser3       = "user3"
	fUser4       = "user4"
	fGroup1      = "group1"
	fGroup2      = "group2"
	fGroup3      = "group3"
	fGroup4      = "group4"
	fSpacedGroup = "group 5"
)

func TestGroupRequest(t *testing.T) {
	client, err := sa.NewClient(fAppID, fAppKey, fHost, fPort, fRealm, true, false)
	if err != nil {
		t.Error(err)
	}
	userToGroupTest, err := singleUserToGroup(client)
	if err != nil {
		t.Error(err)
	}
	if !userToGroupTest {
		t.Error("Single User to Single Group test failed")
	}

	userToGroupsTest, err := singleUserToGroups(client)
	if err != nil {
		t.Error(err)
	}
	if !userToGroupsTest {
		t.Error("Single User to Multiple Groups test failed")
	}

	groupToUserTest, err := singleGroupToUser(client)
	if err != nil {
		t.Error(err)
	}
	if !groupToUserTest {
		t.Error("Single Group to Single User test failed")
	}

	groupToUsersTest, err := singleGroupToUsers(client)
	if err != nil {
		t.Error(err)
	}
	if !groupToUsersTest {
		t.Error("Single Group to Multiple Users test failed")
	}
}

func singleUserToGroup(client *sa.Client) (bool, error) {
	groupRequest := new(Request)
	groupResponse, err := groupRequest.AddUserToGroup(client, fUser1, fGroup1)
	if err != nil {
		return false, err
	}
	if groupResponse.Status == "server_error" {
		return false, errors.New("users endpoint returned server error: " + groupResponse.Message)
	}
	valid, err := groupResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func singleUserToGroups(client *sa.Client) (bool, error) {
	groupRequest := new(Request)
	groups := []string{
		fGroup1,
		fGroup2,
		fGroup3,
		fGroup4,
	}
	groupResponse, err := groupRequest.AddUserToGroups(client, fUser2, groups)
	if err != nil {
		return false, err
	}
	if groupResponse.Status == "server_error" {
		return false, errors.New("users endpoint returned server error: " + groupResponse.Message)
	}
	valid, err := groupResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func singleGroupToUser(client *sa.Client) (bool, error) {
	groupRequest := new(Request)
	groupResponse, err := groupRequest.AddGroupToUser(client, fGroup3, fUser3)
	if err != nil {
		return false, err
	}
	if groupResponse.Status == "server_error" {
		return false, errors.New("users endpoint returned server error: " + groupResponse.Message)
	}
	valid, err := groupResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func singleGroupToUsers(client *sa.Client) (bool, error) {
	groupRequest := new(Request)
	users := []string{
		fUser1,
		fUser2,
		fUser3,
		fUser4,
	}
	groupResponse, err := groupRequest.AddGroupToUsers(client, fGroup4, users)
	if err != nil {
		return false, err
	}
	if groupResponse.Status == "server_error" {
		return false, errors.New("users endpoint returned server error: " + groupResponse.Message)
	}
	valid, err := groupResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}
