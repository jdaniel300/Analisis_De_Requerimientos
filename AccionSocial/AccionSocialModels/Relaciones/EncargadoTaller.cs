using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Relaciones
{
    public class EncargadoTaller
    {
        public int Id { get; set; }
        public int IdTaller { get; set;}
        public int IdUsuario { get; set;}
        public DateTime FechaAsigmacion { get; set;}

        public Taller taller { get; set;}
        public Usuario usuario { get; set; } 
    }
}
