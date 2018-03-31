using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace OAuth.Net.Tests
{
    public class TestHelper
    {
        private readonly string _apiKey;
        private readonly string _secret;
        private readonly string _authToken;
        private readonly string _authTokenSecret;

        public TestHelper(string apiKey, string secret, string authToken, string authTokenSecret)
        {
            _apiKey = apiKey;
            _secret = secret;
            _authToken = authToken;
            _authTokenSecret = authTokenSecret;
        }

        /// <summary>
        /// Using reflection, it will call the method that computes the oauth signature
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public string ComputeOAuthSignature(HttpRequestMessage request, string nonce, string timestamp, string oauthVersion="1.0a")
        {
            OAuth.OAuthMessageHandler msgHandler = new OAuthMessageHandler(_apiKey, _secret, _authToken, _authTokenSecret, new TestOAuthProvider(nonce, timestamp, oauthVersion));

            // get access to the method.

            MethodInfo getAuthHeaderMethod = msgHandler.GetType().GetMethod("GetAuthenticationHeaderForRequest",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                null,
                new Type[] { typeof(HttpRequestMessage) },
                null);

            Task<string> taskResult= getAuthHeaderMethod.Invoke(msgHandler, new object[] { request }) as Task<string>;
            string headerString = taskResult.Result;

            // extract the oauth signature
            string[] elems = headerString.Split(',');
            foreach (var item in elems)
            {
                if (item.StartsWith("oauth_signature"))
                {
                    return item.Split('=')[1];
                }
            }

            return null;
        }
    }
}
