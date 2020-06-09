using IdSrvEf.App.Data;
using IdSrvEf.App.Security;
using IdSrvEf.Core.Entities;
using IdSrvEf.Infra.Email;
using IdSrvEf.Infra.Identity.TokenProviders;
using IdSrvEf.Infra.IdentityServer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Reflection;

namespace IdSrvEf.Infra
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
        {
            if (environment.IsEnvironment("Testing"))
            {
                // Add Identity Infra
                services.AddDbContext<AppDbContext>(options =>
                    options.UseInMemoryDatabase(databaseName: "IdServerWithEF"));
            }
            else
            {
                // Add Identity Persistence Infra 
                services.AddDbContext<AppDbContext>(options =>
                        options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"), b => b.MigrationsAssembly(Assembly.GetExecutingAssembly().ToString())));
            }

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4;
                options.Password.RequiredUniqueChars = 2;
                options.Tokens.EmailConfirmationTokenProvider = "emailconfirmation";
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders()
                .AddTokenProvider<EmailConfirmationTokenProvider<ApplicationUser>>("emailconfirmation");

            // set email confirmation token lifespan to 3 days
            services.Configure<EmailConfirmationTokenProviderOptions>(opt =>
                opt.TokenLifespan = TimeSpan.FromDays(3));

            services.ConfigureApplicationCookie(options =>
            {
                // configure login path for return urls
                // https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-3.1&tabs=visual-studio
                options.LoginPath = "/Identity/Account/Login";
                options.AccessDeniedPath = "/Identity/Account/AccessDenied";
            });

            // add super admin user details from config as a singleton service
            IdentityInit identityInit = new IdentityInit();
            configuration.Bind("IdentityInit", identityInit);
            services.AddSingleton(identityInit);

            // add email settings from config as a singleton service
            EmailConfiguration emailConfig = new EmailConfiguration();
            configuration.Bind("EmailSettings", emailConfig);
            services.AddSingleton(emailConfig);

            // Add Email service
            services.AddTransient<IEmailSender, EmailSender>();

            // add identity server
            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
                //.AddInMemoryIdentityResources(Config.Ids)
                //.AddInMemoryApiResources(Config.Apis)
                //.AddInMemoryClients(Config.Clients)
                .AddAspNetIdentity<ApplicationUser>()
                // this adds the config data from DB (clients, resources, CORS)
                // https://docs.identityserver.io/en/release/quickstarts/8_entity_framework.html#adding-migrations
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseNpgsql(configuration.GetConnectionString("DefaultConnection"), bldr => bldr.MigrationsAssembly(Assembly.GetExecutingAssembly().ToString()));
                })
                // this adds the operational data from DB (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b => b.UseNpgsql(configuration.GetConnectionString("DefaultConnection"), bldr => bldr.MigrationsAssembly(Assembly.GetExecutingAssembly().ToString()));
                    // this enables automatic token cleanup. this is optional.
                    options.EnableTokenCleanup = true;
                });

            // not recommended for production - you need to store your key material somewhere secure
            builder.LoadSigningCredentialFrom(configuration["Certificates:Signing"], configuration["Certificates:Password"]);

            return services;
        }
    }
}
