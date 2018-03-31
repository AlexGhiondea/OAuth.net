namespace OAuth
{
    internal class OAuthSignatureDataProvider : IOAuthSignatureData
    {
        private string _oauthVersion;

        public OAuthSignatureDataProvider(OAuthVersion oauthVersion)
        {
            _oauthVersion = OAuth.Helpers.OAuthHelpers.GetOAuthVersionAsString(oauthVersion);
        }

        public string GetNonce() => OAuth.Helpers.OAuthHelpers.GenerateNonce();

        public string GetTimeStamp() => OAuth.Helpers.OAuthHelpers.GenerateTimestamp();

        public string GetOAuthVersion() => _oauthVersion;
    }
}
