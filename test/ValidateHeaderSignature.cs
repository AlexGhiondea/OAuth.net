using System;
using System.Net.Http;
using Xunit;

namespace OAuth.Net.Tests
{
    public class ValidateHeaderSignature
    {
        [Fact]
        public void ValidateHeader1()
        {
            TestHelper th = new TestHelper("1234", "3456", "234", "23424");
            var result = th.ComputeOAuthHeader(new System.Net.Http.HttpRequestMessage(HttpMethod.Get, "http://www.foo.com"));


        }
    }
}
