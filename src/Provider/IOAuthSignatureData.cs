namespace OAuth.Signature
{
    public interface IOAuthSignatureData
    {
        string GetNonce();
        string GetTimeStamp();
        string GetOAuthVersion();
    }
}
