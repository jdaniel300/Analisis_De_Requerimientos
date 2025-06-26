using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels
{
    public class Participantes
    {
        public int Id { get; set; }
        public int IdUsuario { get; set; }
        public int IdTaller { get; set; }

        public DateTime FechaInscripcion { get; set; }
        public bool Estado { get; set; } 

        public Usuario Usuario { get; set; }
        public Taller Taller { get; set; }

    }
}
