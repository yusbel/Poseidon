using Cassandra;

namespace T2C.Security.Token.Ports
{
    public class CassandraBaseRepo
    {
        protected readonly ISession Session;

        public CassandraBaseRepo()
        {
            var cluster = Cluster.Builder().AddContactPoints("52.225.217.231", "52.225.219.223", "52.225.222.210").Build();
            Session = cluster.Connect("ap_demo");
        }
    }
}
