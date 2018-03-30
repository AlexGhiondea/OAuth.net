using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OAuth.Helpers
{
    public static class OAuthHelpers
    {
        // Use a static for this well known date time, no need to re-create it every time.
        static readonly DateTime s_Jan1970 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Normalizes the parameters according to the oAuth spec:
        /// - Sort the parameters lexicografically
        /// - Concatenate them into a query string
        /// </summary>
        public static string NormalizeParameters(List<KeyValuePair<string, string>> parameters)
        {
            // create the encoded list of parameters.
            List<KeyValuePair<string, string>> encodedParameters = new List<KeyValuePair<string, string>>();
            foreach (var pair in parameters)
            {
                // The key/value should be Encoded.
                // This does mean that we will encode this twice but this is according to the way SmugMug 
                // and oAuth works.
                KeyValuePair<string, string> newPair = new KeyValuePair<string, string>(
                    EncodeValue(pair.Key),
                    EncodeValue(pair.Value)
                );
                encodedParameters.Add(newPair);
            }

            encodedParameters.Sort(new Comparison<KeyValuePair<string, string>>((param1, param2) =>
            {
                if (param1.Key == param2.Key)
                {
                    return string.Compare(param1.Value, param2.Value, StringComparison.Ordinal);
                }
                else
                {
                    return string.Compare(param1.Key, param2.Key, StringComparison.Ordinal);
                }
            }));

            StringBuilder normalizedParameters = new StringBuilder();
            foreach (var param in encodedParameters)
            {
                normalizedParameters.AppendFormat("{0}={1}&", param.Key, param.Value);
            }
            normalizedParameters.Remove(normalizedParameters.Length - 1, 1);

            return normalizedParameters.ToString();
        }

        /// <summary>
        /// Encodes the value in the manner required by the oAuth
        /// All values not permitted are encoded as % followed by
        /// the value of the character in HEX
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string EncodeValue(string value)
        {
            // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
            string acceptedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

            StringBuilder encodedValue = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                if (acceptedChars.IndexOf(value[i]) >= 0)
                {
                    encodedValue.Append(value[i]);
                }
                else
                {
                    // encode it
                    var bytes = Encoding.UTF8.GetBytes(new char[] { value[i] });
                    for (int j = 0; j < bytes.Length; j++)
                    {
                        encodedValue.Append('%' + bytes[j].ToString("X2"));
                    }
                }
            }

            return encodedValue.ToString();
        }

        /// <summary>
        /// Gets the absolute URI for a request ( no query strings )
        /// </summary>
        public static string GenerateBaseStringUri(string host)
        {
            return new Uri(host).AbsoluteUri;
        }

        /// <summary>
        /// Generates the base string for the oAuth request
        /// </summary>
        public static string GenerateBaseString(string host, string httpMethod, List<KeyValuePair<string, string>> parameters)
        {
            httpMethod = httpMethod.ToUpperInvariant();
            host = EncodeValue(GenerateBaseStringUri(host));
            string param = EncodeValue(NormalizeParameters(parameters));

            return string.Format("{0}&{1}&{2}", httpMethod, host, param);
        }

        /// <summary>
        /// Gets the timestamp in seconds since January 1970 00:00:00AM
        /// </summary>
        public static string GenerateTimestamp()
        {
            TimeSpan ts = DateTime.Now.ToUniversalTime() - s_Jan1970;
            return ((long)ts.TotalSeconds).ToString();
        }

        /// <summary>
        /// Generate a unique string for each request
        /// </summary>
        public static string GenerateNonce()
        {
            return Guid.NewGuid().ToString("N");
        }

        /// <summary>
        /// Calculate the HMAC-SHA1 digest for the base string
        /// </summary>
        public static string GenerateHMACDigest(string data, string clientSecret, string tokenSecret = "")
        {
            HMACSHA1 hash = new HMACSHA1();
            string key = string.Format("{0}&{1}", EncodeValue(clientSecret), EncodeValue(tokenSecret));

            //the key is the client secret+ "&" + token_secret
            hash.Key = Encoding.UTF8.GetBytes(key);

            byte[] digest = hash.ComputeHash(Encoding.UTF8.GetBytes(data));

            return Convert.ToBase64String(digest);
        }
    }
}
