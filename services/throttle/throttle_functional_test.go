package throttle

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
	fAppID  = ""
	fAppKey = ""
	fHost   = ""
	fRealm  = ""
	fPort   = 443
	fUser   = ""
)

func TestThrottle(t *testing.T) {
	client, err := sa.NewClient(fAppID, fAppKey, fHost, fPort, fRealm, true, false)
	if err != nil {
		t.Error(err)
	}

	resetTest, err := resetThrottle(client)
	if err != nil {
		t.Error(err)
	}
	if !resetTest {
		t.Error("Reset Throttle test failed")
	}

	getTest, err := getThrottle(client)
	if err != nil {
		t.Error(err)
	}
	if !getTest {
		t.Error("Get Throttle test failed")
	}
}

func resetThrottle(client *sa.Client) (bool, error) {
	throttleRequest := new(Request)
	throttleResponse, err := throttleRequest.Put(client, fUser)
	if err != nil {
		return false, err
	}

	valid, err := throttleResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}

func getThrottle(client *sa.Client) (bool, error) {
	throttleRequest := new(Request)
	throttleResponse, err := throttleRequest.Get(client, fUser)
	if err != nil {
		return false, err
	}

	valid, err := throttleResponse.IsSignatureValid(client)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Response signature is invalid")
	}
	return true, nil
}
