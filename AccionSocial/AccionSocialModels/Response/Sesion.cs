using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Response
{
    public class Sesion
    {
        public int Id { get; set; }
        public int IdTaller {get; set;}
        public DateTime Fecha { get; set; }
        public TimeOnly HoraInicio { get; set; }
        public TimeOnly HoraFin { get; set; }
        public string Tema { get; set; }
        public bool Estado { get; set; }

        
    }
}
