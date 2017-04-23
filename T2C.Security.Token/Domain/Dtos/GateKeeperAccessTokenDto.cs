namespace T2C.Security.Token.Domain.Dtos
{
    public class GateKeeperAccessTokenDto
    {
        public string OAuthAccessToken { get; set; }
        public string Signature { get; set; }
        public bool Verified { get; set; }
    }
}