using System.Threading.Tasks;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public interface INonceRepo
    {
        Task<bool> Any(string nonce);
        Task Save(NonceDto dto);
    }
}