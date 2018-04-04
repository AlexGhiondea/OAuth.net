using System;
using System.Linq;
using Xunit;

namespace OAuth.Net.Tests
{
    public class ValidateOAuthVersionAuthenticator
    {
        [Fact]
        public void ValidateDefaultOAuthVersionAuthenticator()
        {
            var authenticator = new OAuthAuthenticator("key", "secret");

            var oauthVersion = GetOAuthVersionFromAuthenticator(authenticator);

            Assert.Equal("1.0", oauthVersion);
        }

        [Fact]
        public void ValidateOAuthVersionOmitAuthenticator()
        {
            var authenticator = new OAuthAuthenticator("key", "secret", OAuthVersion.Omit);

            var oauthVersion = GetOAuthVersionFromAuthenticator(authenticator);

            Assert.Null(oauthVersion);
        }

        [Fact]
        public void ValidateOAuthVersionOneZeroAuthenticator()
        {
            var authenticator = new OAuthAuthenticator("key", "secret", OAuthVersion.OneZero);

            var oauthVersion = GetOAuthVersionFromAuthenticator(authenticator);

            Assert.Equal("1.0", oauthVersion);
        }

        [Fact]
        public void ValidateOAuthVersionOneZeroAAuthenticator()
        {
            var authenticator = new OAuthAuthenticator("key", "secret", OAuthVersion.OneZeroA);

            var oauthVersion = GetOAuthVersionFromAuthenticator(authenticator);

            Assert.Equal("1.0a", oauthVersion);
        }

        private string GetOAuthVersionFromAuthenticator(OAuthAuthenticator authenticator)
        {
            var url = authenticator.CreateGetRequestTokenAddress("http://example.com", "GET", "http://example.com/callback");
            return new Uri(url).Query
                .Split('&')
                .Select(parameter => parameter.Split('='))
                .SingleOrDefault(keyValue => keyValue[0] == "oauth_version")?[1];
        }
    }
}
