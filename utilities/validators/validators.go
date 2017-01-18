package validators

import "net/http"
import "fmt"

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

var (
	allowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut}
	typeList       = []string{"call", "sms", "email"}
)

// ValidateHTTPMethod :
//	exportable helper to validate expected http method verbs.
func ValidateHTTPMethod(str string) bool {
	for _, v := range allowedMethods {
		if v == str {
			return true
		}
	}
	return false
}

// ValidateRequestType :
//	exportable helper to validate expected request type for adhoc otp delivery.
func ValidateRequestType(str string) bool {
	for _, v := range typeList {
		if v == str {
			return true
		}
	}
	return false
}

// ValidateClientParams :
// exportable helper to validate expected client parameters for calling NewClient()
func ValidateClientParams(params map[string]string) (bool, error) {
	for k, v := range params {
		if isNil(v) {
			return false, fmt.Errorf("%v is required for creating a new client", k)
		}
	}
	return true, nil
}

// isNill :
//	non-exportable helper to nil check a string.
func isNil(s string) bool {
	if len(s) <= 0 {
		return true
	}
	return false
}
