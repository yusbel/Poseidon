namespace T2C.Security.Token.Ports.Dtos
{
    public class PublicKeyDto
    {
        public string EnduserId { get; set; }
        public string DeviceType { get; set; }
        public string PublicKeyBase64String { get; set; }
    }

    public class GateKeeperKeysDto
    {
        public string GateKepperId { get; set; }
        public string PrivateBase64String { get; set; }
        public string PublicKeyBase64String { get; set; }
    }

    public class NonceDto
    {
        public string Nonce { get; set; }
        public string OAuthAccessTokenBase64String { get; set; }
        public string Signature { get; set; }
    }
}
