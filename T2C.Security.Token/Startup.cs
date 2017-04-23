using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Swashbuckle.AspNetCore.Swagger;
using Swashbuckle.AspNetCore.SwaggerGen;
using T2C.Security.Token.Domain;
using T2C.Security.Token.Domain.Interfaces;
using T2C.Security.Token.Ports;


namespace T2C.Security.Token
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();
            services.AddSingleton<IPublicKeyRepo, PublicKeyRepo>();
            services.AddSingleton<IGateKeeperKeyRepo, GateKeeperKeyRepo>();
            services.AddSingleton<INonceRepo, NonceRepo>();
            services.AddSingleton<Common.ILogger, Common.Logger>();
            services.AddTransient<IDeviceRequestValidator, DeviceRequestValidator>();
            services.AddTransient<IAccessTokenAggregateRoot, AccessTokenAggregateRoot>();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Info { Title = "Security API", Version = "v1" });
            });
            services.AddMvcCore().AddApiExplorer();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();
            
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Security API");
            });
            app.UseMvc();
        }
    }
}
