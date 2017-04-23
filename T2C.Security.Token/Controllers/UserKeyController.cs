using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using T2C.Security.Token.Ports;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Controllers
{
    [Produces("application/json")]
    [Route("api/UserKey")]
    public class UserKeyController : Controller
    {
        private readonly IPublicKeyRepo _publicKeyRepo;

        public UserKeyController(IPublicKeyRepo publicKeyRepo)
        {
            _publicKeyRepo = publicKeyRepo;
        }
        
        [HttpGet]
        public async Task<string> Get(string userId, string deviceType)
        {
            if(String.IsNullOrWhiteSpace(userId) || String.IsNullOrWhiteSpace(deviceType))
                throw new ArgumentException("Invalid request");
            return await _publicKeyRepo.GetPublicKey(userId, deviceType);
        }
        
        [HttpPost]
        public async Task Post([FromBody]PublicKeyDto requestDto)
        {
            if(String.IsNullOrWhiteSpace(requestDto.EnduserId) || String.IsNullOrWhiteSpace(requestDto.DeviceType.ToString()) || String.IsNullOrWhiteSpace(requestDto.PublicKeyBase64String))
                throw new ArgumentException("Invalid request");

            await _publicKeyRepo.Save(requestDto);
        }


        [HttpGet]
        [Route("health")]
        public string Health()
        {
            return "Up";
        }
    }
}