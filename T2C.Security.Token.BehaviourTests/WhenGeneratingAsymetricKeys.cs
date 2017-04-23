using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using T2C.Security.Common;
using T2C.Security.Token.Domain.Enums;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.BehaviourTests
{
    [TestClass]
    public class WhenGeneratingAsymetricKeys : BaseTest
    {
        [TestMethod]
        public void Given_User_and_DeviceType_Then_SaveKey()
        {
            //arrange
            var rsaProvider = new RSACryptoServiceProvider(2048);
            var publicKey = rsaProvider.PublicKeyToXmlString();
            var toPost = new PublicKeyDto
            {
                EnduserId = "yusbel_gmail_com_Android_TD_Spend",
                DeviceType = DeviceType.AndroidPhone.ToString(),
                PublicKeyBase64String = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(publicKey))
            };

            //act
            var client = new HttpClient();
            var jsonToPost = JsonConvert.SerializeObject(toPost);
            var content = new StringContent(jsonToPost, Encoding.UTF8, "application/json");
            var result = client.PostAsync(new Uri($"{BaseMobileSecurity}/api/UserKey"), content).Result;

            //assert
            Microsoft.VisualStudio.TestTools.UnitTesting.Assert.IsTrue(result.IsSuccessStatusCode);
        }
        

        [TestMethod]
        public void HelloWorld_Test()
        {
            Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(1,1);
        }
    }
}
