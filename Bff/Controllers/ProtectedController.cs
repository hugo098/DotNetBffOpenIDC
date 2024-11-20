using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Bff.Controllers;

[Authorize]
public class MySecureController : Controller
{
    // This action requires authentication
    [HttpGet("hello-world")]
    public async Task<IActionResult> GetSecureData()
    {
        string? accessToken = await HttpContext.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectParameterNames.AccessToken);

        return Ok(accessToken);
    }
}