using Microsoft.Extensions.DependencyInjection;

namespace IdSrvEf.Infra.IdentityServer
{
    public static class IdentityServerBuilderExtensions
    {
        // this extension class code is taken from https://kimsereyblog.blogspot.com/2018/07/self-signed-certificate-for-identity.html
        // guide to generate certificate using openssl - https://benjii.me/2017/06/creating-self-signed-certificate-identity-server-azure/
        // download openssl from https://slproweb.com/products/Win32OpenSSL.html
        // openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout example.key -out example.crt -subj "/CN=example.com" -days 3650
        // openssl pkcs12 -export -out example.pfx -inkey example.key -in example.crt -certfile example.crt
        // use certlm.msc to manage certificates and trusted certificates - http://woshub.com/how-to-create-self-signed-certificate-with-powershell/
        public static IIdentityServerBuilder LoadSigningCredentialFrom(this IIdentityServerBuilder builder, string certPath, string certPass)
        {
            if (!string.IsNullOrWhiteSpace(certPath))
            {
                //builder.AddSigningCredential(new X509Certificate2(certPath, certPass, X509KeyStorageFlags.MachineKeySet));
                builder.AddSigningCredential(certPath);
            }
            else
            {
                builder.AddDeveloperSigningCredential();
            }

            return builder;
        }
    }
}
