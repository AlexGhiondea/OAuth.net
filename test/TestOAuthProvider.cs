using System;
using System.Collections.Generic;
using System.Text;

namespace OAuth.Net.Tests
{
    public class TestOAuthProvider : OAuth.IOAuthRandomnessProvider
    {
        string _nonce;
        string _timestamp;
        string _oauthVersion;
        public TestOAuthProvider(string nonce, string timestamp, string version="1.0a")
        {
            _nonce = nonce;
            _timestamp = timestamp;
            _oauthVersion = version;
        }

        public string GenerateNonce()
        {
            return _nonce;
        }

        public string GenerateTimeStamp()
        {
            return _timestamp;
        }

        public string OAuthVersion()
        {
            return _oauthVersion;
        }
    }
}
