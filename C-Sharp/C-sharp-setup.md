## Bing Custom Search ARM – C#

This guide explains how to set up and run the C# console application that authenticates to Azure and configures Bing Custom Search resources using Azure Resource Manager (ARM).

## Prerequisites

.NET SDK 9.0 or later <br>
An Azure subscription with sufficient permissions <br>
Azure CLI installed and logged in (only required for azurecli mode) <br>

## Setup and Build 

Create a project folder, create the C# console project, and move into it by running <br>

> mkdir Bing-custom <br>
> cd Bing-custom <br> 
> dotnet new console -n Bing-custom --framework net9.0 <br>

Place Program.cs, .env, allowed.json and blocked.json in the same Bing-custom folder alongside Bing-custom.csproj. <br>
From the Bing-custom folder, add the required NuGet packages by running<br> 

> dotnet add .\Bing-custom.csproj package Azure.Identity --source nuget.org <br>
> dotnet add .\Bing-custom.csproj package DotNetEnv --source nuget.org<br> 
> 
verify with <br>  

> dotnet list .\Bing-custom.csproj package <br> 
> 
and build the project using <br>

> dotnet build .\Bing-custom.csproj<br>

## Running the Application
The application supports five authentication modes. We explicitly use <br>
--project .\Bing-custom.csproj <br>
to ensure the correct project is executed, even if commands are run from another directory or the repository contains multiple projects.


> dotnet run --project .\Bing-custom.csproj<br>
This defaults to service principal authentication.<br>

> dotnet run --project .\Bing-custom.csproj -- --mode azurecli<br> 
This uses the currently logged-in Azure CLI account.<br>

> dotnet run --project .\Bing-custom.csproj -- --mode interactive<br> 
This uses browser-based interactive sign-in.<br>

> dotnet run --project .\Bing-custom.csproj -- --mode serviceprincipal<br> 
This is equivalent to the default mode but explicitly specified.<br>

> dotnet run --project .\Bing-custom.csproj -- --mode managedidentity<br> 
This uses managed identity and does not work on a local laptop; it only works on Azure-hosted resources such as VMs, App Service, or AKS.

Notes

Keep Program.cs, .env, and any JSON configuration files in the same folder as Bing-custom.csproj.
Use --project when running to avoid accidentally executing the wrong project.
Interactive authentication behavior may vary depending on Entra ID tenant policies.
