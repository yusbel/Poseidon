using System;
using System.Linq;
using System.Threading.Tasks;
using T2C.Security.Token.Ports.Dtos;

namespace T2C.Security.Token.Ports
{
    public class PublicKeyRepo : CassandraBaseRepo, IPublicKeyRepo
    {

        public async Task<string> GetPublicKey(string userIdentitifer, string deviceType)
        {
            var ps = Session.Prepare("Select public_key from mob_users_keys where mob_user_id = ? and device_type = ?");
            var statement = ps.Bind(userIdentitifer, deviceType);
            var result = await Session.ExecuteAsync(statement);
            var key = (result.FirstOrDefault()[0]).ToString();
            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(key));
        }

        public async Task<bool> Save(PublicKeyDto dto)
        {
            var ps = Session.Prepare("insert into mob_users_keys (mob_user_id, device_type, public_key) values (?, ? , ?)");
            var statement = ps.Bind(dto.EnduserId, dto.DeviceType, dto.PublicKeyBase64String);
            await Session.ExecuteAsync(statement);
            return true;
        }
    }
}