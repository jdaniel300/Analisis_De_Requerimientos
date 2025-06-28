using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Response
{
    public class AuthResult
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}
