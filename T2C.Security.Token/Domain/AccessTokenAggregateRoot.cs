using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using T2C.Security.Common;
using T2C.Security.Token.Domain.Dtos;
using T2C.Security.Token.Domain.Interfaces;
using T2C.Security.Token.Ports;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Domain
{
    public class AccessTokenAggregateRoot : BaseAggregateRoot, IAccessTokenAggregateRoot
    {
        private readonly IDeviceRequestValidator _requestValidator;
        private readonly IGateKeeperKeyRepo _gateKeeperKeyRepo;
        private readonly INonceRepo _nonceRepo;

        public AccessTokenAggregateRoot(IDeviceRequestValidator requestValidator, 
                                        IGateKeeperKeyRepo gateKeeperKeyRepo, 
                                        INonceRepo nonceRepo, 
                                        ILogger logger): base(logger)
        {
            if (requestValidator == null || gateKeeperKeyRepo == null)
                throw new ArgumentNullException();

            Id = Constants.GateKeeper.GateKeeperId;
            _requestValidator = requestValidator;
            _gateKeeperKeyRepo = gateKeeperKeyRepo;
            _nonceRepo = nonceRepo;
        }

        public async Task<GateKeeperAccessTokenDto> Create(AccessTokenRequestDto requestDto)
        {
            var signature = String.Empty;
            if (!await _requestValidator.IsRequestValid(requestDto))
                throw new ArgumentException("Invalid request");
            //Verify nonce
            if (await _nonceRepo.Any(requestDto.Nonce))
                throw new ArgumentException("Invalid request");

            //Create digitally signed gatekeeper access token
            var privateKey = (await _gateKeeperKeyRepo.GetPrivateAndPublicKey(Constants.GateKeeper.GateKeeperId, Constants.GateKeeper.EphemeralVersion)).Item1;
            var rsa = new RSACryptoServiceProvider(Constants.Crypto.KeySizes);
            rsa.FromXmlString(privateKey);
            byte[] baseString = System.Text.Encoding.UTF8.GetBytes($"{requestDto.OAuthAccessTokenBase64String}:{true}");
            signature = Convert.ToBase64String(rsa.SignData(baseString, SHA1.Create()));
            TrackNonce(requestDto);
            return new GateKeeperAccessTokenDto
            {
                OAuthAccessToken = requestDto.OAuthAccessTokenBase64String,
                Verified = true,
                Signature = signature
            };
        }

        public async Task<GateKeeperAccessTokenDto> CreateParallel(AccessTokenRequestDto requestDto)
        {
            var signature = String.Empty;
            await Task.WhenAll(
                Task.Run(async () =>
                {
                    if (!await _requestValidator.IsRequestValid(requestDto))
                        throw new ArgumentException("Invalid request");
                }), 
                Task.Run(async () =>
                {
                    //Verify nonce
                    if (await _nonceRepo.Any(requestDto.Nonce))
                        throw new ArgumentException("Invalid request");

                }), 
                Task.Run(async () =>
                {
                    //Create digitally signed gatekeeper access token
                    var privateKey = (await _gateKeeperKeyRepo.GetPrivateAndPublicKey(Constants.GateKeeper.GateKeeperId, Constants.GateKeeper.EphemeralVersion)).Item1;
                    var rsa = new RSACryptoServiceProvider(Constants.Crypto.KeySizes);
                    rsa.FromXmlString(privateKey);
                    byte[] baseString = System.Text.Encoding.UTF8.GetBytes($"{requestDto.OAuthAccessTokenBase64String}:{true}");
                    signature = Convert.ToBase64String(rsa.SignData(baseString, SHA1.Create()));
                }));
            TrackNonce(requestDto);
            return new GateKeeperAccessTokenDto
            {
                OAuthAccessToken = requestDto.OAuthAccessTokenBase64String,
                Verified = true,
                Signature = signature
            };
        }

        private Task TrackNonce(AccessTokenRequestDto requestDto)
        {
            return _nonceRepo.Save(new NonceDto
            {
                Nonce = requestDto.Nonce,
                OAuthAccessTokenBase64String = requestDto.OAuthAccessTokenBase64String,
                Signature = requestDto.Signature
            }).ContinueWith(task =>
            {
                if (task.IsCanceled || task.IsFaulted)
                {

                    var ex = task.Exception;
                }
            });
        }
    }
}
