using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OAuth.net
{
    public class OAuthSignature
    {
        const string oauth_consumer_key = "oauth_consumer_key";
        const string oauth_token = "oauth_token";
        const string oauth_signature_method = "oauth_signature_method";
        const string oauth_timestamp = "oauth_timestamp";
        const string oauth_nonce = "oauth_nonce";
        const string oauth_signature = "oauth_signature";
        const string oauth_token_secret = "oauth_token_secret";
        const string oauth_version = "oauth_version";
        const string oauth_callback = "oauth_callback";

        private readonly string ApiKey;
        private readonly string Secret;
        public OAuthSignature(string apiKey, string secret)
        {
            ApiKey = apiKey;
            Secret = secret;
        }

        public string CreateRequest(string url, string method, string tokSecret, params object[] args)
        {
            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string,string>(oauth_consumer_key, ApiKey),
                new KeyValuePair<string,string>(oauth_nonce, OAuthHelpers.GenerateNonce() ),
                new KeyValuePair<string,string>(oauth_timestamp, OAuthHelpers.GenerateTimestamp() ),
                new KeyValuePair<string,string>(oauth_signature_method, "HMAC-SHA1"),
                new KeyValuePair<string,string>(oauth_version, "1.0"),
            };

            for (int i = 0; i < args.Length; i += 2)
            {
                parameters.Add(new KeyValuePair<string, string>(args[i].ToString(), args[i + 1].ToString()));
            }

            string baseString = OAuthHelpers.GenerateBaseString(url, method, parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, Secret, tokSecret));

            parameters.Add(new KeyValuePair<string, string>(oauth_signature, sig));

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
            return uri + "?" + CreateRequest(uri, method, string.Empty, "oauth_callback", callback);
        }

        public string CreateAuthorizeAddress(string uri, string requestToken, string access, string permissions)
        {
            return uri + "?" + requestToken + string.Format("&Access={0}&Permissions={1}", access, permissions);
        }

        public string CreateGetAccessTokenAddress(string uri, string method, string tokenSecret, string token, string verifierPIN)
        {
            return uri + "?" + CreateRequest(uri, method, tokenSecret, "oauth_token", token, "oauth_verifier", verifierPIN);
        }

        internal string GetAuthenticationHeaderForRequest(string url, string method, string tokSecret, string token)
        {
            List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string,string>(oauth_consumer_key, ApiKey),
                new KeyValuePair<string,string>(oauth_nonce, OAuthHelpers.GenerateNonce() ),
                new KeyValuePair<string,string>(oauth_timestamp, OAuthHelpers.GenerateTimestamp() ),
                new KeyValuePair<string,string>(oauth_signature_method, "HMAC-SHA1"),
                new KeyValuePair<string,string>(oauth_version, "1.0"),
                new KeyValuePair<string,string>(oauth_token, token),
            };

            string baseString = OAuthHelpers.GenerateBaseString(url, method, parameters);
            string sig = OAuthHelpers.EncodeValue(OAuthHelpers.GenerateHMACDigest(baseString, Secret, tokSecret));

            parameters.Add(new KeyValuePair<string, string>(oauth_signature, sig));

            StringBuilder sb = new StringBuilder();

            foreach (var param in parameters)
            {
                if (param.Key.StartsWith("oauth"))
                {
                    sb.AppendFormat("{0}={1},", param.Key, HttpUtility.HtmlEncode(param.Value));
                }
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString();
        }
    }
}
