# OAuth.net

[![NuGet version](https://img.shields.io/nuget/v/Oauth.Net.svg?style=flat)](https://www.nuget.org/packages/oauth.net)
[![Nuget downloads](https://img.shields.io/nuget/dt/Oauth.Net.svg?style=flat)](https://www.nuget.org/packages/oauth.net)
![Build And Test](https://github.com/AlexGhiondea/OAuth.net/workflows/Build%20And%20Test/badge.svg)
[![codecov](https://codecov.io/gh/AlexGhiondea/OAuth.net/branch/master/graph/badge.svg)](https://codecov.io/gh/AlexGhiondea/Oauth.Net)
[![MIT License](https://img.shields.io/github/license/AlexGhiondea/Oauth.Net.svg)](https://github.com/AlexGhiondea/Oauth.Net/blob/master/LICENSE)
========

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
