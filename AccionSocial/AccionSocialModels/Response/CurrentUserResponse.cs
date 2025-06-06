using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Response
{
    public class CurrentUserResponse
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string NombreCompleto { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }
}
