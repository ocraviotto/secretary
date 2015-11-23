# Secretary
Secrets distribution for dynamic container environments

## TODO

* Encrypt with svc key when deploying. Test for svckey in app env by encryption configenvelope with candidate nonce and config/master keys and then string compare
* Lighter looks for a type:pem in maven when deploying and send it along in service_public_key
* Needs to declare as insecure service to get autogenerated svckey by lighter. Error if enc envvar present by no key in maven or insecure deckared
* Sign/encrypt query parameters in decrypt request to daemon (pack all of them into envelope)
* Setuid secretary-cgi that decrypts the master key to avoid 
  giving `secretary daemon` direct access to master private key.
