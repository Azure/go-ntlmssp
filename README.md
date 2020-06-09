# go-ntlmssp
Golang package that provides NTLM/Negotiate authentication over HTTP

[![GoDoc](https://godoc.org/github.com/launchdarkly/go-ntlmssp?status.svg)](https://godoc.org/github.com/launchdarkly/go-ntlmssp) [![Circle CI](https://circleci.com/gh/launchdarkly/go-ntlmssp.svg?style=svg)](https://circleci.com/gh/launchdarkly/go-ntlmssp)

This is a fork of [github.com/Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp), with minor changes for use in the [LaunchDarkly Go SDK](https://github.com/launchdarkly/go-server-sdk).

Protocol details from https://msdn.microsoft.com/en-us/library/cc236621.aspx
Implementation hints from http://davenport.sourceforge.net/ntlm.html

This package only implements authentication, no key exchange or encryption. It
only supports Unicode (UTF16LE) encoding of protocol strings, no OEM encoding.
This package implements NTLMv2.

# Usage

```
url, user, password := "http://www.example.com/secrets", "robpike", "pw123"
client := &http.Client{
  Transport: ntlmssp.Negotiator{
    RoundTripper:&http.Transport{},
  },
}

req, _ := http.NewRequest("GET", url, nil)
req.SetBasicAuth(user, password)
res, _ := client.Do(req)
```

-----
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
