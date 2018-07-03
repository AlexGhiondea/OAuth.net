# OAuth.net

[![NuGet version](https://badge.fury.io/nu/Oauth.Net.svg)](https://badge.fury.io/nu/Oauth.Net)
[![Build status](https://ci.appveyor.com/api/projects/status/github/AlexGhiondea/Oauth.Net?branch=master&svg=true)](https://ci.appveyor.com/project/AlexGhiondea/Oauth.Net)
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
