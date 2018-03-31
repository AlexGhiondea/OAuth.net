namespace OAuth
{
    public interface IOAuthRandomnessProvider
    {
        string GenerateNonce();
        string GenerateTimeStamp();
    }
}
