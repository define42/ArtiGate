//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newtonsoftVersion pins an immutable nuget.org release whose nuspec declares
// no dependencies for modern target frameworks, so the collect mirrors
// exactly one package and the restore needs nothing else.
const newtonsoftVersion = "13.0.3"

// TestNuget mirrors a package from the real NuGet v3 flat container across
// the diode and restores+runs a program against the high side's regenerated
// v3 feed with the real dotnet SDK, the mirror configured as the only source.
func TestNuget(t *testing.T) {
	stack.Prepare(t)
	dotnet := requireTool(t, "dotnet")

	res := stack.Collect(t, "nuget", map[string]any{
		"packages":     []string{"Newtonsoft.Json@" + newtonsoftVersion},
		"resolve_deps": false, // older-TFM nuspec groups would pull the netstandard1.x closure
	})
	if res.ExportedModules != 1 {
		t.Fatalf("expected exactly the pinned package, got %d unit(s)", res.ExportedModules)
	}
	stack.WaitImported(t, "nuget", res.Sequence)

	// The service index is what the client bootstraps from; the registration
	// leaf is what package details/search follow.
	code, body := httpGet(t, stack.HighURL+"/nuget/v3/index.json")
	if code != 200 || !strings.Contains(string(body), "PackageBaseAddress/3.0.0") {
		t.Fatalf("service index = %d %s", code, body)
	}
	code, _ = httpGet(t, stack.HighURL+"/nuget/v3/registration/newtonsoft.json/"+newtonsoftVersion+".json")
	if code != 200 {
		t.Fatalf("registration leaf = %d", code)
	}

	tmp := t.TempDir()
	tfm := nugetE2ETargetFramework(t, dotnet, tmp)
	writeFile(t, filepath.Join(tmp, "nuget.config"), fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="artigate" value="%s/nuget/v3/index.json" protocolVersion="3" allowInsecureConnections="true" />
  </packageSources>
</configuration>
`, stack.HighURL))
	writeFile(t, filepath.Join(tmp, "app.csproj"), fmt.Sprintf(`<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>%s</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="%s" />
  </ItemGroup>
</Project>
`, tfm, newtonsoftVersion))
	writeFile(t, filepath.Join(tmp, "Program.cs"), `using Newtonsoft.Json;

public static class Program
{
    public static void Main()
    {
        System.Console.WriteLine(JsonConvert.SerializeObject(new { mirror = "ok" }));
    }
}
`)

	// dotnet run may prepend restore chatter on non-tty output, so match the
	// program's line rather than the whole stream.
	out := runStdout(t, tmp, nugetE2EEnv(tmp), dotnet, "run", "--project", "app.csproj")
	if !strings.Contains(out, `{"mirror":"ok"}`) {
		t.Fatalf("dotnet run printed %q", out)
	}
	// The package really came from the mirror: it sits in the isolated
	// global-packages folder the restore was pointed at.
	nupkg := filepath.Join(tmp, "packages", "newtonsoft.json", newtonsoftVersion,
		"newtonsoft.json."+newtonsoftVersion+".nupkg")
	if _, err := os.Stat(nupkg); err != nil {
		t.Fatalf("restored package archive missing: %v", err)
	}
}

// nugetE2EEnv isolates the SDK: a fresh global-packages folder (so the
// restore cannot be satisfied from a warm cache) and no telemetry chatter.
func nugetE2EEnv(tmp string) []string {
	return []string{
		"NUGET_PACKAGES=" + filepath.Join(tmp, "packages"),
		"DOTNET_CLI_TELEMETRY_OPTOUT=1",
		"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
		"DOTNET_NOLOGO=1",
	}
}

// nugetE2ETargetFramework derives the TFM matching the installed SDK, so the
// build needs no reference packages beyond what the SDK bundles.
func nugetE2ETargetFramework(t *testing.T, dotnet, tmp string) string {
	t.Helper()
	out := strings.TrimSpace(runStdout(t, tmp, nugetE2EEnv(tmp), dotnet, "--version"))
	major, _, ok := strings.Cut(out, ".")
	if !ok || major == "" {
		t.Fatalf("cannot derive a target framework from dotnet version %q", out)
	}
	return "net" + major + ".0"
}
