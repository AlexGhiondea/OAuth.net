using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OAuth.Net.Tests
{
    public class TestHttpMessageHandler : HttpMessageHandler
    {
        private static readonly HttpResponseMessage OkResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK);

        public List<HttpRequestMessage> SentMessages { get; } = new List<HttpRequestMessage>();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SentMessages.Add(request);
            return Task.FromResult(OkResponse);
        }
    }
}