using Microsoft.AspNetCore.Authorization;

namespace idunno.Authentication.Demo
{
    public class AlwaysFailRequirement : 
        AuthorizationHandler<AlwaysFailRequirement>, 
        IAuthorizationRequirement
    {
        protected override void Handle(
            AuthorizationContext context, 
            AlwaysFailRequirement requirement)
        {
            return;
        }
    }
}
