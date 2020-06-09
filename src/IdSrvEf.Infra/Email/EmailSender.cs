using Microsoft.AspNetCore.Identity.UI.Services;
using System;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace IdSrvEf.Infra.Email
{
    public class EmailSender : IEmailSender
    {
        EmailConfiguration EmailConfig { get; }
        public EmailSender(EmailConfiguration emailConfig)
        {
            EmailConfig = emailConfig;
        }
        public async Task SendEmailAsync(string emailAddresses, string subject, string htmlMessage)
        {
            Console.WriteLine("Sending mail...");

            MailMessage message = new MailMessage
            {
                From = new MailAddress(EmailConfig.MailAddress),
                Subject = subject,
                IsBodyHtml = true,
                Body = htmlMessage
            };
            // we assume emails will be sepated by ";"
            foreach (string emailId in emailAddresses.Split(";"))
            {
                message.To.Add(emailId);
            }

            // since we are not getting entries in sent mail, we will add mail manually
            if (!emailAddresses.Split(";").ToList().Any(em => em == EmailConfig.MailAddress))
            {
                // add sender mail if not present in to addresses
                message.To.Add(EmailConfig.MailAddress);
            }

            using (var smtpClient = new SmtpClient())
            {
                smtpClient.Host = EmailConfig.HostName;
                smtpClient.Port = 587;
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(EmailConfig.Username, EmailConfig.Password, EmailConfig.Domain);
                smtpClient.Timeout = (60 * 5 * 1000);
                await smtpClient.SendMailAsync(message);
            }


            Console.WriteLine("Done sending mail...");
        }
    }
}
