using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Serilog;

WebApplicationBuilder? builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

ConfigurationManager? configuration = builder.Configuration;

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration.GetSection("Logging:Serilog")) // Read from "Logging:Serilog"
    .Enrich.FromLogContext()
    .WriteTo.Console()  // Optional: Log to the console
    .CreateLogger();

builder.Logging.AddSerilog();

builder.Services
    .AddAuthorization()
    .AddAuthentication(options => configuration.Bind("Authentication", options))
    .AddCookie(options =>
    {
        options.Cookie.SameSite = SameSiteMode.None;
    })
    .AddOpenIdConnect(options =>
    {
        configuration.Bind("OpenIdConnect", options);

        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                Log.Information("Redirecting to OIDC provider for authentication: {RedirectUri}", context.ProtocolMessage.RedirectUri);

                // Log the code_challenge and code_verifier
                string? codeVerifier = context.Properties.Items["code_verifier"];

                string? codeChallenge = context.ProtocolMessage.Code;

                Log.Information("Code Verifier: {CodeVerifier}", codeVerifier);
                Log.Information("Code Challenge: {CodeChallenge}", codeChallenge);

                if (!context.Request.Path.StartsWithSegments("/auth"))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.HandleResponse();
                }

                return Task.CompletedTask;
            },

            // Log when an authorization code is received
            OnAuthorizationCodeReceived = context =>
            {
                Log.Information("Authorization code received from OIDC provider: {Code}", context.TokenEndpointRequest?.Code);

                return Task.CompletedTask;
            },

            // Log when the OIDC login is successful
            OnTokenResponseReceived = context =>
            {
                Log.Information("OIDC token response received. Access token: {AccessToken}", context.TokenEndpointResponse.AccessToken);
                return Task.CompletedTask;
            },

            // Log when the user logs out
            OnSignedOutCallbackRedirect = context =>
            {
                Log.Information("User logged out. Redirecting to: {RedirectUri}", context.Properties?.RedirectUri);
                return Task.CompletedTask;
            },
        };
    });

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173") // Vite's default dev server
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

WebApplication? app = builder.Build();

app.UseCors();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();


app.Run();
