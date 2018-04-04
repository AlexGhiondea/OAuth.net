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
            TestHelper th = new TestHelper("apiKey", "secret", "token", "tokenSecret");

            Assert.Equal("1.0", await th.ComputeOAuthVersionAsync(GetDummyRequest(), "nonce", "timestamp", OAuthVersion.OneZero));
        }

        [Fact]
        public async Task ValidateOAuthVersionOmitHandler()
        {
            TestHelper th = new TestHelper("apiKey", "secret", "token", "tokenSecret");

            Assert.Null(await th.ComputeOAuthVersionAsync(GetDummyRequest(), "nonce", "timestamp", OAuthVersion.Omit));
        }

        [Fact]
        public async Task ValidateOAuthVersionOneZeroHandler()
        {
            TestHelper th = new TestHelper("apiKey", "secret", "token", "tokenSecret");

            Assert.Equal("1.0", await th.ComputeOAuthVersionAsync(GetDummyRequest(), "nonce", "timestamp", OAuthVersion.OneZero));
        }

        [Fact]
        public async Task ValidateOAuthVersionOneZeroAHandler()
        {
            TestHelper th = new TestHelper("apiKey", "secret", "token", "tokenSecret");
            Assert.Equal("1.0a", await th.ComputeOAuthVersionAsync(GetDummyRequest(), "nonce", "timestamp", OAuthVersion.OneZeroA));
        }

        private HttpRequestMessage GetDummyRequest()
        {
            return new HttpRequestMessage(HttpMethod.Get, "http://example.com");
        }
    }
}
