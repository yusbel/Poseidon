using System;
using System.Linq;
using System.Threading.Tasks;
using T2C.Security.Token.Domain;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public class GateKeeperKeyRepo : CassandraBaseRepo, IGateKeeperKeyRepo
    {
        public async Task<bool> Any(string gateKepperId)
        {
            var ps = Session.Prepare("Select gate_keeper_id from mob_gate_keeper_keys where gate_keeper_id = ? and ephemeral_key_version = ?");
            var statement = ps.Bind(gateKepperId, Constants.GateKeeper.EphemeralVersion);
            var result = await Session.ExecuteAsync(statement);
            return result.Any();
        }

        public async Task<Tuple<string,string>> GetPrivateAndPublicKey(string gateKepperId, string ephemeralVersion)
        {
            var ps = Session.Prepare("Select private_key, public_key from mob_gate_keeper_keys where gate_keeper_id = ? and ephemeral_key_version = ?");
            var statement = ps.Bind(gateKepperId, ephemeralVersion);
            var result = await Session.ExecuteAsync(statement);
            var privateKey = String.Empty;
            var publicKey = String.Empty;
            foreach (var row in result)
            {
                privateKey = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(row.GetValue<string>("private_key")));
                publicKey = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(row.GetValue<string>("public_key")));
            }
            return new Tuple<string, string>(privateKey, publicKey);
        }

        public async Task Save(GateKeeperKeysDto dto)
        {
            var ps = Session.Prepare("insert into mob_gate_keeper_keys (gate_keeper_id, ephemeral_key_version, private_key, public_key) values (?, ?, ? , ?)");
            var statement = ps.Bind(dto.GateKepperId, Constants.GateKeeper.EphemeralVersion, dto.PrivateBase64String, dto.PublicKeyBase64String);
            await Session.ExecuteAsync(statement);
        }
    }
}
