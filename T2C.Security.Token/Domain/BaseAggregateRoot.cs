using T2C.Security.Common;

namespace T2C.Security.Token.Domain
{
    public class BaseAggregateRoot
    {
        protected readonly ILogger Logger;
        protected string Id;

        public BaseAggregateRoot(ILogger logger)
        {
            Logger = logger;
        }
    }
}