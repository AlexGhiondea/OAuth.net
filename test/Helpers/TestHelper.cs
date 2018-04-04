using System;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;

namespace OAuth.Net.Tests
{
    public class TestHelper
    {
        private readonly string _apiKey;
        private readonly string _clientSecret;
        private readonly string _authToken;
        private readonly string _authTokenSecret;

        public TestHelper(string apiKey, string secret, string authToken, string authTokenSecret)
        {
            _apiKey = apiKey;
            _clientSecret = secret;
            _authToken = authToken;
            _authTokenSecret = authTokenSecret;
        }

        /// <summary>
        /// Using reflection, it will call the method that computes the oauth signature
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public async Task<string> ComputeOAuthSignatureAsync(HttpRequestMessage request, string nonce, string timestamp, OAuthVersion version)
        {
            using (OAuthMessageHandler msgHandler = new OAuthMessageHandler(
                _apiKey,
                _clientSecret,
                _authToken,
                _authTokenSecret,
                new TestOAuthProvider(
                    nonce,
                    timestamp,
                    version)))
            {
                return await GetOAuthParameterFromHandlerAsync(msgHandler, request, "oauth_signature");
            }
        }

        public async Task<string> ComputeOAuthVersionAsync(HttpRequestMessage request, string nonce, string timestamp, OAuthVersion version)
        {
            using (OAuthMessageHandler msgHandler = new OAuthMessageHandler(
                _apiKey,
                _clientSecret,
                _authToken,
                _authTokenSecret,
                new TestOAuthProvider(
                    nonce,
                    timestamp,
                    version)))
            {
                return await GetOAuthParameterFromHandlerAsync(msgHandler, request, "oauth_version");
            }
        }

        private async Task<string> GetOAuthParameterFromHandlerAsync(OAuthMessageHandler handler, HttpRequestMessage request, string requestedParameter)
        {
            var testHandler = new TestHttpMessageHandler();
            handler.InnerHandler = testHandler;

            using (var httpClient = new HttpClient(handler, disposeHandler: false))
            {
                await httpClient.SendAsync(request);
            }

            var request2 = testHandler.SentMessages.Single();
            var authHeaderParameter = request.Headers.Authorization.Parameter;

            // extract the parameter
            string[] elems = authHeaderParameter.Split(',');
            return elems.SingleOrDefault(x => x.StartsWith($"{requestedParameter}="))?.Split('=')[1];
        }
    }
}
