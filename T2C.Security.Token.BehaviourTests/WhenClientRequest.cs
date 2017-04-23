using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using T2C.Security.Common;
using T2C.Security.Token.Domain;
using T2C.Security.Token.Domain.Dtos;
using T2C.Security.Token.Domain.Enums;
using T2C.Security.Token.Ports;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.BehaviourTests
{
    [TestClass]
    public class WhenClientRequest : BaseTest
    {
        [TestMethod]
        public void Given_A_Valid_OAuth_AccessToken_Signed_Then_Validate_Return_True()
        {
            //arrange
            var rsa = CreateAndPublishKey();
            var request = new AccessTokenRequestDto();
            request.OAuthAccessTokenBase64String = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("First-AccessToken"));
            request.DeviceType = DeviceType.AndroidPhone;
            request.EndUserMobileIdentifier = "yusbel_gmail_Android_TD_Spend";
            request.Nonce = "garcia.diaz";
            byte[] baseString = System.Text.Encoding.UTF8.GetBytes($"{request.OAuthAccessTokenBase64String}:{request.Nonce}:{request.EndUserMobileIdentifier}");
            request.Signature = Convert.ToBase64String(rsa.SignData(baseString, SHA1.Create()));

            //act
            DeviceRequestValidator validator = new DeviceRequestValidator(new PublicKeyRepo());
            var result = validator.IsRequestValid(request).Result;

            AccessTokenAggregateRoot aggregateRoot = new AccessTokenAggregateRoot(validator, new GateKeeperKeyRepo(), new NonceRepo(), new Logger());
            var created = aggregateRoot.Create(request).Result;
            
            //assert
            Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(result);
        }

        [TestMethod]
        public void HelloWorld_Test()
        {
            Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(1,1);
        }

        private RSACryptoServiceProvider CreateAndPublishKey()
        {
            var rsaProvider = new RSACryptoServiceProvider(2048);
            var publicKey = rsaProvider.PublicKeyToXmlString();
            PublishPublicKey(publicKey).Wait();
            return rsaProvider;
        }

        private async Task PublishPublicKey(string key)
        {
            var toPost = new PublicKeyDto
            {
                EnduserId = "yusbel_gmail_Android_TD_Spend",
                DeviceType = DeviceType.AndroidPhone.ToString(),
                PublicKeyBase64String = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(key))
            };

            var client = new HttpClient();
            var jsonToPost = JsonConvert.SerializeObject(toPost);
            var content = new StringContent(jsonToPost, Encoding.UTF8, "application/json");
            var result = await client.PostAsync(new Uri($"{BaseMobileSecurity}/api/UserKey"), content);
        }

    }
}
