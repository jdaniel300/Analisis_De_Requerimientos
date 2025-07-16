namespace AccionSocialModels.Response
{
    public record CurrentUserResponse(
        int UserId,
        string UserName,
        string Email,
        string NombreCompleto,
        string Telefono,
        List<string> Roles,
        DateTime FechaCreacion,
        DateTime? UltimoAcceso,
        bool Estado);
}
