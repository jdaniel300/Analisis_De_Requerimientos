using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.DTO
{
    public class UsuarioRolDTO
    {
        public ListaUsuariosDTO Usuario {  get; set; }
        public List<string> Roles { get; set; }

    }
}
