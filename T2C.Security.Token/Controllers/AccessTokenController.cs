using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using T2C.Security.Token.Domain.Dtos;
using T2C.Security.Token.Domain.Interfaces;

namespace T2C.Security.Token.Controllers
{
    [Produces("application/json")]
    [Route("api/AccessToken")]
    public class AccessTokenController : Controller
    {
        private readonly IAccessTokenAggregateRoot _accessTokenAgg;

        public AccessTokenController(IAccessTokenAggregateRoot accessTokenAgg)
        {
            _accessTokenAgg = accessTokenAgg;
        }
        
        [HttpGet]
        public string Get(string name)
        {
            return $"Hello {name}";
        }

        // POST api/values
        [HttpPost]
        public async Task Post([FromBody]AccessTokenRequestDto requestDto)
        {
            if(String.IsNullOrWhiteSpace(requestDto.EndUserMobileIdentifier)||
                String.IsNullOrWhiteSpace(requestDto.OAuthAccessTokenBase64String)||
                String.IsNullOrWhiteSpace(requestDto.Nonce)||
                String.IsNullOrWhiteSpace(requestDto.Signature))
              throw new ArgumentException("Invalid request");

            var result = await _accessTokenAgg.CreateParallel(requestDto);
        }
    }
}
