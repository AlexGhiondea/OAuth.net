# OAuth.net
Library to handle the OAuth protocol. Implements http://tools.ietf.org/html/rfc5849

## Transparent authentication

You can register a message handler to the HttpClient you are using that will handle the oAuth signing.

```csharp
            OAuth.OAuthMessageHandler _handler = new OAuth.OAuthMessageHandler(
                oauthToken.ApiKey,
                oauthToken.Secret,
                oauthToken.Token,
                oauthToken.TokenSecret);
            HttpClient client = new HttpClient(_handler);
```
