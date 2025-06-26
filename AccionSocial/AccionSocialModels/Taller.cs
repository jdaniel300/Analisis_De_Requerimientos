using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels
{
    public class Taller
    {
        public int Id { get; set; }
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public string Objetivos { get; set; }
        public string Estado { get; set; }
        public DateTime FechaCreacion { get; set; }
        public DateTime FechaActualizacion { get; set; }
        public Usuario Encargado { get; set; } = null!; // Relación con Usuario
        public int EncargadoId { get; set; } // Clave foránea para Usuario

    }
}
