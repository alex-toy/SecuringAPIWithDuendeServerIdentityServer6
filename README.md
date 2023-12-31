# Securing API with Duende Server (Identity Server 6)

In this project we will take an API application with authentication using .NET identity and we will modify it to use Identity Server(Duende Server 6) for authentication and authorization. Duende Server 6 uses Razor Pages as default UI pages and we will see how to add login logout and register functionality.


## Preparation
The IdentityServer templates for the dotnet CLI are a good starting point for the quickstarts. To install the templates open a console window and type the following command:

```
dotnet new --install Duende.IdentityServer.Templates
```


## MagicVilla_Identity

- install packages
```
Duende.IdentityServer.AspNetIdentity
Microsoft.AspNetCore.Identity.EntityFrameworkCore
Microsoft.AspNetCore.Authentication.OpenIdConnect
Microsoft.AspNetCore.Identity.UI
Microsoft.EntityFrameworkCore.SqlServer
Microsoft.EntityFrameworkCore.Tools
```

- run the project 
<img src="/pictures/identity_server.png" title="identity server"  width="900">


## MagicVilla_Web

- install packages
```
Microsoft.AspNetCore.Authentication.OpenIdConnect
```
- run the Identity, API and Web. Then go to login 
<img src="/pictures/identity_server2.png" title="identity server"  width="900">

