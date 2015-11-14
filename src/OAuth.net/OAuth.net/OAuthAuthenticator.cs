using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

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
        public OAuthAuthenticator(string apiKey, string secret)
        {
            _apiKey = apiKey;
            _secret = secret;
        }

        private string CreateRequest(string url, string method, string tokSecret, params object[] args)
        {
            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string,string>(Constants.oauth_consumer_key, _apiKey),
                new KeyValuePair<string,string>(Constants.oauth_nonce, OAuthHelpers.GenerateNonce() ),
                new KeyValuePair<string,string>(Constants.oauth_timestamp, OAuthHelpers.GenerateTimestamp() ),
                new KeyValuePair<string,string>(Constants.oauth_signature_method, "HMAC-SHA1"),
                new KeyValuePair<string,string>(Constants.oauth_version, Constants.oauth_version_1a),
            };

            for (int i = 0; i < args.Length; i += 2)
            {
                parameters.Add(new KeyValuePair<string, string>(args[i].ToString(), args[i + 1].ToString()));
            }

            string baseString = OAuthHelpers.GenerateBaseString(url, method, parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, _secret, tokSecret));

            parameters.Add(new KeyValuePair<string, string>(Constants.oauth_signature, sig));

            StringBuilder sb = new StringBuilder();

            foreach (var param in parameters)
            {
                sb.AppendFormat("{0}={1}&", param.Key, HttpUtility.HtmlEncode(param.Value));
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

        public string CreateAuthorizeAddress(string uri, string requestToken, string access, string permissions)
        {
            return uri + "?" + requestToken + string.Format("&Access={0}&Permissions={1}", access, permissions);
        }

        public void ParseRequestTokens(string tokens, out string reqToken, out string reqTokenSecret)
        {
            string[] elem = tokens.Split('&');

            reqToken = elem[0].Split('=')[1];
            reqTokenSecret = elem[1].Split('=')[1];
        }
    }
}
