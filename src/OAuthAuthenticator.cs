using OAuth.Helpers;
using System.Collections.Generic;
using System.Text;

namespace OAuth
{
    /// <summary>
    /// Use this class to drive the OAuth process. 
    /// There are three requests that need to be made:
    ///  - GetRequestToken 
    ///  - GetAuthorizationUri
    ///  - GetAccessToken
    /// </summary>
    public class OAuthAuthenticator
    {
        private readonly string _apiKey;
        private readonly string _secret;
        private readonly string _versionParameter;

        public OAuthAuthenticator(string apiKey, string secret, OAuthVersionParameter versionParameter = OAuthVersionParameter.OneZeroA)
        {
            _apiKey = apiKey;
            _secret = secret;
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
        }

        private string CreateRequest(string url, string method, string tokSecret, params object[] args)
        {
            SortedSet<KeyValuePair<string, string>> parameters = new SortedSet<KeyValuePair<string, string>>(new OAuthParameterComparer())
            {
                new KeyValuePair<string,string>(Constants.oauth_consumer_key, _apiKey),
                new KeyValuePair<string,string>(Constants.oauth_nonce, OAuthHelpers.GenerateNonce() ),
                new KeyValuePair<string,string>(Constants.oauth_timestamp, OAuthHelpers.GenerateTimestamp() ),
                new KeyValuePair<string,string>(Constants.oauth_signature_method, "HMAC-SHA1"),
            };

            if (!string.IsNullOrEmpty(_versionParameter))
            {
                parameters.Add(new KeyValuePair<string, string>(Constants.oauth_version, _versionParameter));
            }

            for (int i = 0; i < args.Length; i += 2)
            {
                parameters.Add(new KeyValuePair<string, string>(args[i].ToString(), args[i + 1].ToString()));
            }

            string baseString = OAuthHelpers.GenerateBaseString(url, method, parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, OAuthHelpers.CreateHashKeyBytes(_secret, tokSecret)));

            parameters.Add(new KeyValuePair<string, string>(Constants.oauth_signature, sig));

            StringBuilder sb = new StringBuilder();

            foreach (var param in parameters)
            {
                sb.AppendFormat("{0}={1}&", param.Key, System.Net.WebUtility.HtmlEncode(param.Value));
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString();
        }

        public string CreateGetRequestTokenAddress(string uri, string method, string callback)
        {
            return uri + "?" + CreateRequest(uri, method, string.Empty, Constants.oauth_callback, callback);
        }

        public string CreateGetAccessTokenAddress(string uri, string method, string tokenSecret, string token, string verifierPIN)
        {
            return uri + "?" + CreateRequest(uri, method, tokenSecret, Constants.oauth_token, token, Constants.oauth_verifier, verifierPIN);
        }

        public string CreateAuthorizeAddress(string uri, string requestToken)
        {
            return uri + "&" + requestToken;
        }

        public void ParseRequestTokens(string tokens, out string reqToken, out string reqTokenSecret)
        {
            string[] elem = tokens.Split('&');

            reqToken = elem[0].Split('=')[1];
            reqTokenSecret = elem[1].Split('=')[1];
        }
    }
}
