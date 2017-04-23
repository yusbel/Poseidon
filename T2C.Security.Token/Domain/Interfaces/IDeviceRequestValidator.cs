using System;
using System.Threading.Tasks;
using T2C.Security.Token.Domain.Dtos;

namespace T2C.Security.Token.Domain.Interfaces
{
    public interface IDeviceRequestValidator
    {
        Task<bool> IsRequestValid(AccessTokenRequestDto request, Func<AccessTokenRequestDto, string> signatureCreator = null);
    }
}