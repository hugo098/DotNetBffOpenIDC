using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace Bff.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : Controller
{
    [HttpGet("check_session")]
    public ActionResult<IDictionary<string, string>> CheckSession()
    {
        if (User.Identity?.IsAuthenticated != true)
            return Unauthorized();

        Dictionary<string, string>? claims = User.Claims.ToDictionary(claim => claim.Type, claim => claim.Value);

        return Ok(claims);
    }

    [HttpGet("login")]
    public ActionResult<IDictionary<string, string>> Login()
    {
        return Challenge(new AuthenticationProperties 
        { 
            RedirectUri = "http://localhost:5173"
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // Get the current user's ID token
        string? idToken = await HttpContext.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, "id_token");

        if (string.IsNullOrEmpty(idToken))
        {
            return Ok(new { message = "No active session" });
        }

        // Construct the Keycloak logout URL
        string? keycloakLogoutUrl = $"http://localhost:8080/realms/homebanking/protocol/openid-connect/logout?post_logout_redirect_uri={Url.Action("PostLogoutRedirect", "Auth", null, Request.Scheme)}";

        keycloakLogoutUrl += $"&id_token_hint={idToken}";

        // Sign out from the local ASP.NET Core session
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

        // Send HTTP request to Keycloak to log the user out (server-side)
        using (HttpClient httpClient = new())
        {
            await httpClient.GetAsync(keycloakLogoutUrl);
        }

        // Return a response indicating the logout was processed
        return Ok(new { message = "Logout successful" });
    }

    [HttpGet("post-logout-redirect")]
    public IActionResult PostLogoutRedirect()
    {
        // Redirect back to the frontend after Keycloak logout
        return Redirect("http://localhost:5173/");
    }
}