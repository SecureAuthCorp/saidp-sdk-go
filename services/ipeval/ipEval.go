package ipeval

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"

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

const endpoint = "/api/v1/ipeval"

// Response :
//	Response struct that will be populated after the post request.
type Response struct {
	IPEvaluation IPEvaluation   `json:"ip_evaluation,omitempty"`
	Status       string         `json:"status"`
	Message      string         `json:"message"`
	RawJSON      string         `json:"-"`
	HTTPResponse *http.Response `json:"-"`
}

// Request :
//	Request struct to build the required post parameters.
// Fields:
//	[Required] UserId: the username that you want to evaluate.
//	[Required] EvalType: currently, only 'risk' is supported. Sets the eval type.
//	[Required] IpAddress: the IP Address of the user to be evaluated.
type Request struct {
	UserID    string `json:"user_id"`
	EvalType  string `json:"type"`
	IPAddress string `json:"ip_address"`
}

// IPEvaluation :
//	Struct providing data from the post request.
type IPEvaluation struct {
	Method        *string            `json:"method"`
	IP            *string            `json:"ip"`
	RiskFactor    *float32           `json:"risk_factor"`
	RiskColor     *string            `json:"risk_color"`
	RiskDesc      *string            `json:"risk_desc"`
	GeoLoc        *GeoLoc            `json:"geoloc"`
	Factoring     *Factoring         `json:"factoring"`
	FactoringDesc *FactorDescription `json:"factor_description"`
}

// GeoLoc :
//	Struct providing data from the post request.
type GeoLoc struct {
	Country      *string `json:"country"`
	CountryCode  *string `json:"country_code"`
	Region       *string `json:"region"`
	RegionCode   *string `json:"region_code"`
	City         *string `json:"city"`
	Latitude     *string `json:"latitude"`
	Longtitude   *string `json:"longtitude"`
	Isp          *string `json:"internet_service_provider"`
	Organization *string `json:"organization"`
}

// Factoring :
//	Struct providing data from the post request.
type Factoring struct {
	Latitude       float32 `json:"latitude"`
	Longitude      float32 `json:"longitude"`
	ThreatType     float32 `json:"threatType"`
	ThreatCategory float32 `json:"threatCategory"`
}

// FactorDescription :
//	Struct providing data from the post request.
type FactorDescription struct {
	GeoContinent      string `json:"geoContinent"`
	GeoCountry        string `json:"geoCountry"`
	GeoCountryCode    string `json:"geoCountryCode"`
	GeoCountryCF      string `json:"geoCountryCF"`
	GeoRegion         string `json:"geoRegion"`
	GeoState          string `json:"geoState"`
	GeoStateCode      string `json:"geoStateCode"`
	GeoStateCF        string `json:"geoStateCF"`
	GeoCity           string `json:"geoCity"`
	GeoCityCF         string `json:"geoCityCF"`
	GeoPostalCode     string `json:"geoPostalCode"`
	GeoAreaCode       string `json:"geoAreaCode"`
	GeoTimeZone       string `json:"geoTimeZone"`
	GeoLatitude       string `json:"geoLatitude"`
	GeoLongitude      string `json:"geoLongitude"`
	Dma               string `json:"dma"`
	Msa               string `json:"msa"`
	ConnectionType    string `json:"connectionType"`
	LineSpeed         string `json:"lineSpeed"`
	IPRoutingType     string `json:"ipRoutingType"`
	GeoAsn            string `json:"geoAsn"`
	Sld               string `json:"sld"`
	Tld               string `json:"tld"`
	Organization      string `json:"organization"`
	Carrier           string `json:"carrier"`
	AnonymizerStatus  string `json:"anonymizer_status"`
	ProxyLevel        string `json:"proxyLevel"`
	ProxyType         string `json:"proxyType"`
	ProxyLastDetected string `json:"proxyLastDetected"`
	HostingFacility   string `json:"hostingFacility"`
	ThreatType        string `json:"threatType"`
	ThreatCategory    string `json:"threatCategory"`
}

// Post :
//	Executes a post to the adaptauth endpoint.
// Parameters:
// 	[Required] r: should have all the required fields of the struct populated before using.
//	[Required] c: passing in the client containing authorization and host information.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) Post(c *sa.Client) (*Response, error) {
	jsonRequest, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	httpRequest, err := c.BuildPostRequest(endpoint, string(jsonRequest))
	if err != nil {
		return nil, err
	}
	httpResponse, err := c.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	ipEvalResponse := new(Response)
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, ipEvalResponse); err != nil {
		return nil, err
	}
	ipEvalResponse.RawJSON = string(body)
	httpResponse.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	ipEvalResponse.HTTPResponse = httpResponse
	httpResponse.Body.Close()
	return ipEvalResponse, nil
}

// EvaluateIP :
//	Helper function for making IpEval Posts
// Parameters:
//	[Required] c: passing in the client containing authorization and host information.
//	[Required] userId: the user you wish to evaluate via adaptive auth.
//	[Required] ipAddress: the ip address of the user being evaluated.
// Returns:
//	Response: Struct marshaled from the Json response from the API endpoints.
//	Error: If an error is encountered, response will be nil and the error must be handled.
func (r *Request) EvaluateIP(c *sa.Client, userID string, ipAddress string) (*Response, error) {
	r.UserID = userID
	r.EvalType = "risk"
	r.IPAddress = ipAddress
	ipEvalResponse, err := r.Post(c)
	if err != nil {
		return nil, err
	}
	return ipEvalResponse, nil
}

//IsSignatureValid :
//	Helper function to validate the SecureAuth Response signature in X-SA-SIGNATURE
// Parameters:
//	[Required] r: response struct with HTTPResponse
//	[Required] c: passing in the client with application id and key
// Returns:
//	bool: if true, computed signature matches X-SA-SIGNATURE. if false, computed signature does not match.
//	error: If an error is encountered, bool will be false and the error must be handled.
func (r *Response) IsSignatureValid(c *sa.Client) (bool, error) {
	saDate := r.HTTPResponse.Header.Get("X-SA-DATE")
	saSignature := r.HTTPResponse.Header.Get("X-SA-SIGNATURE")
	var buffer bytes.Buffer
	buffer.WriteString(saDate)
	buffer.WriteString("\n")
	buffer.WriteString(c.AppID)
	buffer.WriteString("\n")
	buffer.WriteString(r.RawJSON)
	raw := buffer.String()
	byteKey, _ := hex.DecodeString(c.AppKey)
	byteData := []byte(raw)
	sig := hmac.New(sha256.New, byteKey)
	sig.Write([]byte(byteData))
	computedSig := base64.StdEncoding.EncodeToString(sig.Sum(nil))
	if computedSig != saSignature {
		return false, nil
	}
	return true, nil
}
