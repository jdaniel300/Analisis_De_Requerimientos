namespace AccionSocialModels.Response
{
    public class LoginResponse
    {
        public string Token { get; set; }
        public UserData User { get; set; }

        public class UserData
        {
            public string userName { get; set; }
            public string email { get; set; }
            public string nombreCompleto { get; set; }
            public List<string> roles { get; set; }
        }
    }
}
