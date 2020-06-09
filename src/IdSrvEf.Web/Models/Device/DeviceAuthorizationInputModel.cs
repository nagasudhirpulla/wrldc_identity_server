using IdSrvEf.Web.Models.Consent;

namespace IdSrvEf.Web.Models.Device
{
    public class DeviceAuthorizationInputModel : ConsentInputModel
    {
        public string UserCode { get; set; }
    }
}
