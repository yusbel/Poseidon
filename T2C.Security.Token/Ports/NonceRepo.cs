using System.Linq;
using System.Threading.Tasks;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public class NonceRepo : CassandraBaseRepo, INonceRepo
    {
        public async Task<bool> Any(string nonce)
        {
            var ps = Session.Prepare("Select mob_nonce_value from mob_nonces where mob_nonce_value = ?");
            var statement = ps.Bind(nonce);
            var result = await Session.ExecuteAsync(statement);
            return result.Any();
        }

        public async Task Save(NonceDto dto)
        {
            var ps = Session.Prepare("insert into mob_nonces (mob_nonce_value, access_token, signature) values (?, ? , ?)");
            var statement = ps.Bind(dto.Nonce, dto.OAuthAccessTokenBase64String, dto.Signature);
            await Session.ExecuteAsync(statement);
        }
    }
}
