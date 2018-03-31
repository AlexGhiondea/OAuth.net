using System;
using System.Net.Http;
using Xunit;

namespace OAuth.Net.Tests
{
    public class ValidateHeaderSignature
    {
        [Fact]
        public void ValidateSignature1()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "http://www.foo.com/"), "d63f7c3ecbcb4b63950c1a418a8d68ce", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=d63f7c3ecbcb4b63950c1a418a8d68ce,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=Q%2FzBeRiPDZFUdMQHJyIoD%2BmVxkk%3D", result);
        }
        [Fact]
        public void ValidateSignature2()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "https://www.foo.com/"), "ecc0248a5bb24049a12a2fd68b1fdd36", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=ecc0248a5bb24049a12a2fd68b1fdd36,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=FWTCA%2F0ecBYWJvv3ufnfsr9GCEk%3D", result);
        }
        [Fact]
        public void ValidateSignature3()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "http://www.foo.com/?param1=value1"), "049d1506cea44b4d9f47d1507392c2f9", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=049d1506cea44b4d9f47d1507392c2f9,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=K6IBBq0q7Nv1oac%2BF4SHw5OSSaU%3D", result);
        }
        [Fact]
        public void ValidateSignature4()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "https://www.foo.com/?param1=value1&param2=value2"), "ddfb04dbed154ac9aeade556c14202dc", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=ddfb04dbed154ac9aeade556c14202dc,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=PazW%2FIVb6D%2Bsn5Z73z2jg79U8k8%3D", result);
        }
        [Fact]
        public void ValidateSignature5()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "https://www.foo.com/?param1=value1&param2&param3"), "5e93ad9588dc496fb0486a0110eeaea9", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=5e93ad9588dc496fb0486a0110eeaea9,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=jp%2F1Yh1cHd6yPDgX%2BsbHQV9ITNM%3D", result);
        }
        [Fact]
        public void ValidateSignature6()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "https://www.foo.com/?param1=value1&param2&param3&altParam=$34"), "a3d765e9e945436ea84b12273b136177", "1522478039");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=a3d765e9e945436ea84b12273b136177,oauth_timestamp=1522478039,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=vNBSSnUXEIw9NUEZay9%2FzgFlw10%3D", result);
        }
        [Fact]
        public void ValidateSignature7()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Post, "https://www.foo.com/?Zed=one&Alpha&Beta"), "90e2ef68cf1c4949b7eb10eccbf28ded", "1522478309");
            Assert.Equal("oauth_consumer_key=1234,oauth_nonce=90e2ef68cf1c4949b7eb10eccbf28ded,oauth_timestamp=1522478309,oauth_signature_method=HMAC-SHA1,oauth_version=1.0a,oauth_token=234,oauth_signature=ixPe0T85xtBNamcPP4cvATsgVDE%3D", result);
        }
    }
}
