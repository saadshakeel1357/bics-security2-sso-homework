# Exercise for Security 2 class

Your task is to make this simple OpenID Connect application work properly. To do so, you'll need to complete the following tasks, which are also commented in the code:

1. Obtain credentials from https://console.developers.google.com and set environment variables `CLIENTID` and `CLIENTSECRET`.

2. Fix the function randomHex.

3. Validate the digital signature in the `idToken` with the correct Google public key.

4. Check `iss`, `aud`, and `exp`.

5. Add Proof Key for Code Exchange (PKCE) extension to the authorization code flow, using SHA256 code challenge method.

## Submission
Please submit `main.go` inside a `.zip` archive to Moodle. Good luck! :)
