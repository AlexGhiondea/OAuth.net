using System;
using System.Collections.Generic;
using System.Text;

namespace OAuth.Net.Tests
{
    public class TestOAuthProvider : IOAuthSignatureData
    {
        string _nonce;
        string _timestamp;
        string _oauthVersion;
        public TestOAuthProvider(string nonce, string timestamp, string version = "1.0a")
        {
            _nonce = nonce;
            _timestamp = timestamp;
            _oauthVersion = version;
        }

        public string GetNonce() => _nonce;
        public string GetOAuthVersion() => _oauthVersion;
        public string GetTimeStamp() => _timestamp;
    }
}
