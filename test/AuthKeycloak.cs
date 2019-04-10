using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace test
{
    public class AuthKeycloak : System.Web.Http.AuthorizeAttribute
    {
        public override void OnAuthorization(
            System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = new System.Net.Http.HttpResponseMessage(HttpStatusCode.Unauthorized);
            }
            else
            {
                if (!TokenValidation(actionContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "")))
                {
                    actionContext.Response = new System.Net.Http.HttpResponseMessage(HttpStatusCode.Unauthorized);
                }
            }
        }
        public bool TokenValidation(string token)
        {
            try
            {
                var key = Encoding.ASCII.GetBytes("481f0a25-c601-48d5-8b05-30de4ea44d19");
                TokenValidationParameters validationParameters =
                    new TokenValidationParameters
                    {
                        ValidIssuer = "http://192.168.115.19:8080/auth/realms/master",
                        ValidAudiences = new[] { "admin-cli" },
                        IssuerSigningKeys = new[] {new SymmetricSecurityKey(key)}
                    };

                SecurityToken validatedToken;
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                var user = handler.ValidateToken(token, validationParameters, out validatedToken);


                return false;

                //var handler = new JwtSecurityTokenHandler();
                //var tokenS = handler.ReadToken(token) as JwtSecurityToken;
                //var jti = tokenS.Claims.First(claim => claim.Type == "jti").Value;
                //return tokenS.Header["kid"] == "uAL77-1eqsz4et7nbjeWW3j_W8mL6ZHHZbA5A_4RO0s";//Realm Settings -> Keys -> RS256 kid
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

    }
    internal static class AsyncHelper
    {
        private static readonly TaskFactory TaskFactory = new TaskFactory(CancellationToken.None, TaskCreationOptions.None, TaskContinuationOptions.None, TaskScheduler.Default);

        public static void RunSync(Func<Task> func)
        {
            TaskFactory.StartNew(func).Unwrap().GetAwaiter().GetResult();
        }

        public static TResult RunSync<TResult>(Func<Task<TResult>> func)
        {
            return TaskFactory.StartNew(func).Unwrap().GetAwaiter().GetResult();
        }
    }
}