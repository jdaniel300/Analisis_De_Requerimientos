using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.DTO
{
    public class ActualizarUsuarioRequest
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Nombre { get; set; }
        public string Apellidos { get; set; }
        public string PhoneNumber { get; set; }
        public string Rol { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }
}
