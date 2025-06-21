

namespace AccionSocialModels.Response
{
    public class PaginacionResponse <T>
    {
        public int Pagina { get; set; }
        public int TamanoPagina { get; set; }
        public int Total { get; set; }

        public List<T> Datos { get; set; }
    }
}
