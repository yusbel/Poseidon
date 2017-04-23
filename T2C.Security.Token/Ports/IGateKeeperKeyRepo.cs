using System;
using System.Threading.Tasks;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public interface IGateKeeperKeyRepo
    {
        Task Save(GateKeeperKeysDto dto);
        Task<Tuple<string, string>> GetPrivateAndPublicKey(string gateKepperId, string ephemeralVersion);
        Task<bool> Any(string gateKepperId);
    }
}