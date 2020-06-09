using IdSrvEf.Web.Models.Consent;

namespace IdSrvEf.Web.Models.Device
{
    public class DeviceAuthorizationViewModel : ConsentViewModel
    {
        public string UserCode { get; set; }
        public bool ConfirmUserCode { get; set; }
    }
}
