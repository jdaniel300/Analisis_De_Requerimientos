using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccionSocialModels.Response
{
    public class DeleteUserResult
    {
        public bool Succeeded { get; }
        public bool IsUnauthorized { get; }
        public string ErrorMessage { get; }

        private DeleteUserResult(bool succeeded, bool isUnauthorized, string errorMessage)
        {
            Succeeded = succeeded;
            IsUnauthorized = isUnauthorized;
            ErrorMessage = errorMessage;
        }

        public static DeleteUserResult Success() => new DeleteUserResult(true, false, null);
        public static DeleteUserResult Failure(string error) => new DeleteUserResult(false, false, error);
        public static DeleteUserResult Unauthorized(string error) => new DeleteUserResult(false, true, error);
    }
}
