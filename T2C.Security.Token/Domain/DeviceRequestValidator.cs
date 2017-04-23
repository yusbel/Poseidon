using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using T2C.Security.Common;
using T2C.Security.Token.Domain.Dtos;
using T2C.Security.Token.Domain.Interfaces;
using T2C.Security.Token.Ports;

namespace T2C.Security.Token.Domain
{
    public class DeviceRequestValidator : IDeviceRequestValidator
    {
        private readonly IPublicKeyRepo _publicKeyRepo;


        public DeviceRequestValidator(IPublicKeyRepo publicKeyRepo)
        {
            _publicKeyRepo = publicKeyRepo;
        }

        public async Task<bool> IsRequestValid(AccessTokenRequestDto request, Func<AccessTokenRequestDto, string> signatureCreator = null)
        {
            signatureCreator = signatureCreator ?? (accessTokenReq =>
            {
                var baseString = System.Text.Encoding.UTF8.GetBytes($"{request.OAuthAccessTokenBase64String}:{request.Nonce}:{request.EndUserMobileIdentifier}");
                return Convert.ToBase64String(baseString);
            });
           
            var publicKey = await _publicKeyRepo.GetPublicKey(request.EndUserMobileIdentifier, request.DeviceType.ToString());
            if (string.IsNullOrWhiteSpace(publicKey))
                return false;
            var rsaCrypto = new RSACryptoServiceProvider(Constants.Crypto.KeySizes);
            var rsaParam = rsaCrypto.ExportParameters(false);
            rsaCrypto.PublicKeyFromXmlString(publicKey);
            /*rsaParam.Modulus = Convert.FromBase64String(publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", ""));
            rsaCrypto.ImportParameters(rsaParam);*/
            var dataToVerify = signatureCreator(request);
            return rsaCrypto.VerifyData(Convert.FromBase64String(dataToVerify), SHA1.Create(), Convert.FromBase64String(request.Signature));
        }

        public bool IsRequestValid(AccessTokenRequestDto request, RSACryptoServiceProvider rsa, Func<AccessTokenRequestDto, string> signatureCreator = null)
        {
            signatureCreator = signatureCreator ?? (accessTokenReq =>
            {
                var baseString = System.Text.Encoding.UTF8.GetBytes($"{request.OAuthAccessTokenBase64String}:{request.Nonce}:{request.EndUserMobileIdentifier}");
                return Convert.ToBase64String(baseString);
            });
            var dataToVerify = signatureCreator(request);
            var result = rsa.VerifyData(Convert.FromBase64String(dataToVerify), "SHA1", Convert.FromBase64String(request.Signature));
            return result;
        }

    }
}
