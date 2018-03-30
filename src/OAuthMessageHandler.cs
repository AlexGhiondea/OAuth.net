using OAuth.Helpers;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace OAuth
{
    public class OAuthMessageHandler : DelegatingHandler
    {
        private readonly string _apiKey;
        private readonly string _secret;
        private readonly string _authToken;
        private readonly string _authTokenSecret;
        private readonly IOAuthRandomnessProvider _provider;

        public OAuthMessageHandler(string apiKey, string secret, string authToken, string authTokenSecret) :
            this(apiKey, secret, authToken, authTokenSecret, new OAuthRandomnessProvider())
        {
        }
        private readonly KeyValuePair<string, string> _hmacSha1Param;
        private readonly KeyValuePair<string, string> _apiKeyParam;
        private readonly KeyValuePair<string, string> _authTokenParam;
        private readonly KeyValuePair<string, string> _oauthVersionParam;

        // the bytes used for the HMAC-SHA1
        public OAuthMessageHandler(string apiKey, string secret, string authToken, string authTokenSecret, IOAuthRandomnessProvider provider)
        private readonly byte[] _keyBytes; 

        {
            _apiKey = apiKey;
            _secret = secret;
            _authToken = authToken;
            _authTokenSecret = authTokenSecret;
            _provider = provider;
            _hmacSha1Param = new KeyValuePair<string, string>(Constants.oauth_signature_method, "HMAC-SHA1");
            _apiKeyParam = new KeyValuePair<string, string>(Constants.oauth_consumer_key, _apiKey);
            _authTokenParam = new KeyValuePair<string, string>(Constants.oauth_token, _authToken);
            // TODO: incorporate the other PR.
            _oauthVersionParam = new KeyValuePair<string, string>(Constants.oauth_version, Constants.oauth_version_1a);

            _keyBytes = OAuthHelpers.CreateHashKeyBytes(_secret, _authTokenSecret);

            this.InnerHandler = new HttpClientHandler();
        }

        public async Task<string> GetAuthenticationHeaderForRequest(HttpRequestMessage request)
        {
            SortedSet<KeyValuePair<string, string>> parameters = new SortedSet<KeyValuePair<string, string>>(new OAuthParameterComparer())
            {
                // Re-use the parameters that don't change
                new KeyValuePair<string,string>(Constants.oauth_nonce, _provider.GenerateNonce()),
                new KeyValuePair<string,string>(Constants.oauth_timestamp, _provider.GenerateTimeStamp()),
                _apiKeyParam,
                _hmacSha1Param,
                _authTokenParam,
                _oauthVersionParam,

                // Add the parameters that are unique for each call
                new KeyValuePair<string, string>(Constants.oauth_nonce, OAuthHelpers.GenerateNonce()),
                new KeyValuePair<string, string>(Constants.oauth_timestamp, OAuthHelpers.GenerateTimestamp()),
            };

            Uri requestUri = request.RequestUri;
            string baseUri = requestUri.OriginalString;

            // We need to handle the case where the request comes with query parameters, in URL or in body
            string queryString = string.Empty;
            if (!string.IsNullOrEmpty(requestUri.Query))
            {
                baseUri = requestUri.OriginalString.Replace(requestUri.Query, "");
                queryString = requestUri.Query;
            }

            // concatenate the content, if we need to.
            if (request.Content?.Headers.ContentType?.MediaType == "application/x-www-form-urlencoded")
            {
                string requestContent = await request.Content.ReadAsStringAsync();

                queryString = $"{queryString}&{requestContent}";
            }

            foreach (var param in queryString.Split(new char[] { '?', '&' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var values = param.Split('=');
                string name = Uri.UnescapeDataString(values[0]);
                name = name.Replace('+', ' ');
                string value = string.Empty;
                if (values.Length > 1)
                {
                    value = Uri.UnescapeDataString(values[1]);
                    value = value.Replace('+', ' ');
                }
                parameters.Add(new KeyValuePair<string, string>(name, value));
            }

            string baseString = OAuthHelpers.GenerateBaseString(baseUri, request.Method.ToString(), parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, _keyBytes));

            parameters.Add(new KeyValuePair<string, string>(Constants.oauth_signature, sig));

            StringBuilder sb = new StringBuilder();
            foreach (var param in parameters)
            {
                if (param.Key.StartsWith("oauth"))
                {
                    sb.AppendFormat("{0}={1},", param.Key, System.Net.WebUtility.HtmlEncode(param.Value));
                }
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            string header = await GetAuthenticationHeaderForRequest(request);

            request.Headers.Authorization = new AuthenticationHeaderValue(Constants.OAuthAuthenticationHeader, header);

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
