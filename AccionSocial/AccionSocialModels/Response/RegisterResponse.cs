namespace AccionSocialModels.Response
{
    public class RegisterResponse
    {
        public string Message { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}
