# go-ntlmssp
Golang package that provides NTLM/Negotiate authentication over HTTP

Protocol details from https://msdn.microsoft.com/en-us/library/cc236621.aspx
Implementation hints from http://davenport.sourceforge.net/ntlm.html

This package only implements authentication, no key exchange or encryption. It
only supports Unicode (UTF16LE) encoding of protocol strings, no OEM encoding.
This package implements NTLMv2.