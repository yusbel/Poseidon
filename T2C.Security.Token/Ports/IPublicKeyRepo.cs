using System.Threading.Tasks;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public interface IPublicKeyRepo
    {
        Task<string> GetPublicKey(string userIdentitifer, string deviceType);
        Task<bool> Save(PublicKeyDto dto);
    }
}