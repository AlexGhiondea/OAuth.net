namespace OAuth
{
    internal class OAuthRandomnessProvider : IOAuthRandomnessProvider
    {
        public string GenerateNonce()
        {
            return OAuth.Helpers.OAuthHelpers.GenerateNonce();
        }

        public string GenerateTimeStamp()
        {
            return OAuth.Helpers.OAuthHelpers.GenerateTimestamp();
        }
    }
}
