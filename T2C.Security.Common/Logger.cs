namespace T2C.Security.Common
{
    public class Logger : ILogger
    {
        private static readonly NLog.Logger _logger = NLog.LogManager.GetCurrentClassLogger();

        public void Write(string msg)
        {
            _logger.Trace(msg);
        }
    }
}
