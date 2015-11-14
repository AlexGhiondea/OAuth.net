using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http.Handlers;

namespace OAuth.net
{
    public class OAuthMessageHandler : DelegatingHandler
    {
        private readonly string _token;
        private readonly string _tokenSecret;
        private readonly OAuthSignature _oauth;


        public OAuthMessageHandler(string apiKey, string secret, string token, string tokenSecret)
        {
            _oauth = new OAuthSignature(apiKey, secret);
            _token = token;
            _tokenSecret = tokenSecret;

            this.InnerHandler = new HttpClientHandler();
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            string header = _oauth.GetAuthenticationHeaderForRequest(request.RequestUri.ToString(), request.Method.ToString(), _tokenSecret, _token);

            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", header);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
