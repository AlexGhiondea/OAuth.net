using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace OAuth.Net.Tests
{
    public class ValidateOAuthVersionMessageHandler
    {
        [Fact]
        public async Task ValidateDefaultOAuthVersionHandler()
        {
            using (var handler = new OAuthMessageHandler("apiKey", "secret", "authToken", "authTokenSecret"))
            {
                var oauthVersion = await GetOAuthVersionFromHandlerAsync(handler);

                Assert.Equal("1.0", oauthVersion);
            }
        }

        [Fact]
        public async Task ValidateOAuthVersionOmitHandler()
        {
            using (var handler = new OAuthMessageHandler("apiKey", "secret", "authToken", "authTokenSecret", OAuthVersion.Omit))
            {
                var oauthVersion = await GetOAuthVersionFromHandlerAsync(handler);

                Assert.Null(oauthVersion);
            }
        }

        [Fact]
        public async Task ValidateOAuthVersionOneZeroHandler()
        {
            using (var handler = new OAuthMessageHandler("apiKey", "secret", "authToken", "authTokenSecret", OAuthVersion.OneZero))
            {
                var oauthVersion = await GetOAuthVersionFromHandlerAsync(handler);

                Assert.Equal("1.0", oauthVersion);
            }
        }

        [Fact]
        public async Task ValidateOAuthVersionOneZeroAHandler()
        {
            using (var handler = new OAuthMessageHandler("apiKey", "secret", "authToken", "authTokenSecret", OAuthVersion.OneZeroA))
            {
                var oauthVersion = await GetOAuthVersionFromHandlerAsync(handler);

                Assert.Equal("1.0a", oauthVersion);
            }
        }

        private async Task<string> GetOAuthVersionFromHandlerAsync(OAuthMessageHandler handler)
        {
            var testHandler = new TestHttpMessageHandler();
            handler.InnerHandler = testHandler;

            using (var httpClient = new HttpClient(handler, disposeHandler: false))
            {
                await httpClient.GetAsync("http://example.com");
            }

            var request = testHandler.SentMessages.Single();
            var authHeaderParameter = request.Headers.Authorization.Parameter;

            // extract the oauth version
            string[] elems = authHeaderParameter.Split(',');
            return elems.SingleOrDefault(x => x.StartsWith("oauth_version"))?.Split('=')[1];
        }
    }
}
