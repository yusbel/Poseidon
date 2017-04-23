using T2C.Security.Token.Domain.Enums;

namespace T2C.Security.Token.Domain.Dtos
{
    public class AccessTokenRequestDto
    {
        public string OAuthAccessTokenBase64String { get; set; }
        public string Nonce { get; set; }
        public string EndUserMobileIdentifier { get; set; }
        public DeviceType DeviceType { get; set; }
        public string Signature { get; set; }
    }
}