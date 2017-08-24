package dfp

import (
	"errors"
	"fmt"
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
	fAppID           = ""
	fAppKey          = ""
	fHost            = ""
	fRealm           = ""
	fPort            = 443
	fUser            = ""
	fHostAddr        = ""
	fFingerprintID   = ""
	fFingerprintJSON = ``
)

func TestDFPRequest(t *testing.T) {
	client, err := sa.NewClient(fAppID, fAppKey, fHost, fPort, fRealm, true, false)
	if err != nil {
		fmt.Println(err)
	}

	jsDfpTest, err := getJS(client)
	if err != nil {
		t.Error(err)
	}
	if !jsDfpTest {
		t.Error("Get DFP JS test failed")
	}

	validateDfpTest, err := dfpValidate(client)
	if err != nil {
		t.Error(err)
	}
	if !validateDfpTest {
		t.Error("Validate DFP test failed")
	}

	confirmDfpTest, err := dfpConfirm(client)
	if err != nil {
		t.Error(err)
	}
	if !confirmDfpTest {
		t.Error("Confirm DFP test failed")
	}

	scoreDfpTest, err := dfpScore(client)
	if err != nil {
		t.Error(err)
	}
	if !scoreDfpTest {
		t.Error("Score DFP test failed")
	}

	saveDfpTest, err := dfpSave(client)
	if err != nil {
		t.Error(err)
	}
	if !saveDfpTest {
		t.Error("Save DFP test failed")
	}
}

func getJS(client *sa.Client) (bool, error) {
	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.GetDfpJs(client)
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

func dfpValidate(client *sa.Client) (bool, error) {
	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ValidateDfp(client, fUser, fHostAddr, fFingerprintID, fFingerprintJSON)
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

func dfpConfirm(client *sa.Client) (bool, error) {
	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ConfirmDfp(client, fUser, fFingerprintID)
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

func dfpScore(client *sa.Client) (bool, error) {
	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.ScoreDfp(client, fUser, fHostAddr, fFingerprintID, fFingerprintJSON)
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

func dfpSave(client *sa.Client) (bool, error) {
	dfpRequest := new(Request)
	dfpResponse, err := dfpRequest.SaveDfp(client, fUser, fHostAddr, fFingerprintID, fFingerprintJSON)
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
