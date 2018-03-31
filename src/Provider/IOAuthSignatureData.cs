namespace OAuth
{
    public interface IOAuthSignatureData
    {
        string GetNonce();
        string GetTimeStamp();
        string GetOAuthVersion();
    }
}
