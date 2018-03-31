using System;
using System.Collections.Generic;
using System.Text;

namespace OAuth.Net.Tests
{
    public class TestOAuthProvider : OAuth.IOAuthRandomnessProvider
    {
        string _nonce;
        string _timestamp;
        public TestOAuthProvider(string nonce, string timestamp)
        {
            _nonce = nonce;
            _timestamp = timestamp; 
        }

        public string GenerateNonce()
        {
            return _nonce;
        }

        public string GenerateTimeStamp()
        {
            return _timestamp;
        }
    }
}
