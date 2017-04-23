using System.Threading.Tasks;
using T2C.Security.Token.Domain.Dtos;

namespace T2C.Security.Token.Domain.Interfaces
{
    public interface IAccessTokenAggregateRoot
    {
        Task<GateKeeperAccessTokenDto> Create(AccessTokenRequestDto requestDto);
        Task<GateKeeperAccessTokenDto> CreateParallel(AccessTokenRequestDto requestDto);
    }
}