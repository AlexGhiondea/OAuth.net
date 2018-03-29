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
        private readonly string _versionParameter;

        public OAuthMessageHandler(string apiKey, string secret, string authToken, string authTokenSecret, OAuthVersionParameter versionParameter = OAuthVersionParameter.OneZeroA)
        {
            _apiKey = apiKey;
            _secret = secret;
            _authToken = authToken;
            _authTokenSecret = authTokenSecret;
            switch (versionParameter)
            {
                case OAuthVersionParameter.OneZeroA:
                    _versionParameter = Constants.oauth_version_1a;
                    break;
                case OAuthVersionParameter.OneZero:
                    _versionParameter = Constants.oauth_version_1;
                    break;
                case OAuthVersionParameter.Omit:
                default:
                    _versionParameter = string.Empty;
                    break;
            }

            this.InnerHandler = new HttpClientHandler();
        }

        private async Task<string> GetAuthenticationHeaderForRequest(HttpRequestMessage request)
        {
            Uri requestUri = request.RequestUri;
            HttpMethod method = request.Method;

            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string,string>(Constants.oauth_consumer_key, _apiKey),
                new KeyValuePair<string,string>(Constants.oauth_nonce, OAuthHelpers.GenerateNonce() ),
                new KeyValuePair<string,string>(Constants.oauth_timestamp, OAuthHelpers.GenerateTimestamp() ),
                new KeyValuePair<string,string>(Constants.oauth_signature_method, "HMAC-SHA1"),
                new KeyValuePair<string,string>(Constants.oauth_token, _authToken),
            };

            if (!string.IsNullOrEmpty(_versionParameter))
            {
                parameters.Add(new KeyValuePair<string, string>(Constants.oauth_version, _versionParameter));
            }

            string baseUri = requestUri.OriginalString;

            // We need to handle the case where the request comes with query parameters, in URL or in body
            string queryString = string.Empty;
            if (!string.IsNullOrEmpty(requestUri.Query))
            {
                baseUri = requestUri.OriginalString.Replace(requestUri.Query, "");
                queryString = requestUri.Query;
            }

            if (request.Content.Headers.ContentType.MediaType == "application/x-www-form-urlencoded")
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

            string baseString = OAuthHelpers.GenerateBaseString(baseUri, method.ToString(), parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, _secret, _authTokenSecret));

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
