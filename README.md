# saidp-sdk-go

Go SDK for SecureAuth IdP API

saipd-sdk-go is a package that allows access to SecureAuth's REST api set. The goal of this package is to provide an easy and standard method to implement SecureAuth's API in a Go project.

The current SDK version 1.0.0 is written to support SecureAuth IdP 9.0 and newer.

This is a community driven project. If you would like to contribute, please fork and update. Changes will be reviewed then added to the project.

## Requirements:
* Go 1.6 or newer

## Usage:
~~~~
client, err := sa.NewClient("af1b351845ec47968b27debd9cd4ce53", "101db0347fdf71dab63cd965b8782ff6ba0f8f1c91e8cf52f970d1267e0fb453", "company.secureauth.com", 443, SecureAuth1, true, false)
if err != nil {
    panic(err)
}
factors := new(Request)
factorResponse, err := factors.Get(client, "user")
if err != nil {
	panic(err)
}
~~~~