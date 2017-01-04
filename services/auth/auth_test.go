package auth

import (
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
	appID       = ""
	appKey      = ""
	host        = "idp.host.com"
	realm       = "secureauth1"
	port        = 443
	user        = "user"
	pass        = "password"
	kba         = ""
	oathDevice  = ""
	pushDevice  = ""
	phoneNumber = "5558645309"
)

func TestAuthRequest(t *testing.T) {
	client, err := sa.NewClient(appID, appKey, host, port, realm, true, false)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	authRequest := new(Request)
	//valUserResp, err := authRequest.ValidateUser(client, user)
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Validate User:")
	//fmt.Println(valUserResp)
	//valPassResp, err := authRequest.ValidatePassword(client, user, pass)
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Validate Password:")
	//fmt.Println(valPassResp)
	//valKbaResp, err := authRequest.ValidateKba(client, user, kba, "KBQ1")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Validate KBA:")
	//fmt.Println(valKbaResp)
	//valOathResp, err := authRequest.ValidateOath(client, user, "123456", oathDevice)
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Validate Oath:")
	//fmt.Println(valOathResp)
	//valPinResp, err := authRequest.ValidatePin(client, user, "1234")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Validate PIN:")
	//fmt.Println(valPinResp)
	//sendCallResp, err := authRequest.SendCallOtp(client, user, "Phone2")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Send Call OTP:")
	//fmt.Println(sendCallResp)
	// sendSMSResp, err := authRequest.SendSMSOtp(client, user, "Phone1")
	// if err != nil {
	// 	fmt.Println(err)
	// 	t.FailNow()
	// }
	// fmt.Println("Send SMS OTP:")
	// fmt.Println(sendSMSResp)
	//sendEmailResp, err := authRequest.SendEmailOtp(client, user, "Email1")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Send Email OTP:")
	//fmt.Println(sendEmailResp)
	//sendPushNotifyResp, err := authRequest.SendPushNotify(client, user, pushDevice)
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Send Push OTP:")
	//fmt.Println(sendPushNotifyResp)
	//sendPushAcceptResp, err := authRequest.SendPushAccept(client, user, pushDevice, "Test Company", "Test App", "192.168.0.1")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Send Push to Accept:")
	//fmt.Println(sendPushAcceptResp)
	//pushStatusResp, err := authRequest.CheckPushAcceptStatus(client, sendPushAcceptResp.RefId, 60, 5)
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Push to Accept Status:")
	//fmt.Println(pushStatusResp)
	//helpDeskResp, err := authRequest.SendHelpDesk(client, user, "HelpDesk1")
	//if err != nil {
	//	fmt.Println(err)
	//	t.FailNow()
	//}
	//fmt.Println("Send HelpDesk OTP:")
	//fmt.Println(helpDeskResp)
	adhocResp, err := authRequest.SendOtpAdHoc(client, user, phoneNumber, "sms", false)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	fmt.Println("Send AdHock SMS OTP")
	fmt.Println(adhocResp)
}
