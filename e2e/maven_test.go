//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mavenPom drives both sides of the Maven test. The low side collects with
// exactly this pom (its collector runs `mvn dependency:go-offline` over it
// and bundles the entire resulting local repository, plugins included), and
// the client builds the same pom against the mirror — so with the same mvn
// binary on both sides the resolved closures are identical by construction.
// Only elements the low side's pom sanitizer accepts may appear here:
// coordinates, packaging, properties, and dependencies.
const mavenPom = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example.e2e</groupId>
  <artifactId>consumer</artifactId>
  <version>0.0.1</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>` + commonsLang3Version + `</version>
    </dependency>
  </dependencies>
</project>
`

// commonsLang3Version pins an immutable Maven Central release.
const commonsLang3Version = "3.17.0"

// TestMaven mirrors a pom's full dependency+plugin closure from Maven
// Central, then compiles a Java program against the high side with the real
// mvn (mirrorOf * — every artifact and plugin must come from the mirror)
// and runs it with plain java.
func TestMaven(t *testing.T) {
	stack.Prepare(t)
	mvn := requireTool(t, "mvn")
	javaBin := requireTool(t, "java")

	res := stack.Collect(t, "maven", map[string]any{"pom_xml": mavenPom})
	stack.WaitImported(t, "maven", res.Sequence)

	tmp := t.TempDir()
	proj := filepath.Join(tmp, "proj")
	writeFile(t, filepath.Join(proj, "pom.xml"), mavenPom)
	writeFile(t, filepath.Join(proj, "src", "main", "java", "e2e", "Main.java"), `package e2e;

import org.apache.commons.lang3.StringUtils;

public class Main {
    public static void main(String[] args) {
        System.out.println(StringUtils.swapCase("ArtiGate E2E"));
    }
}
`)
	// Maven >= 3.8 blocks plain-HTTP mirrors via its built-in
	// "maven-default-http-blocker" (mirrorOf external:http:*), which
	// deliberately excludes localhost — a plain-HTTP loopback mirror works.
	writeFile(t, filepath.Join(tmp, "settings.xml"), fmt.Sprintf(`<settings>
  <mirrors>
    <mirror>
      <id>artigate</id>
      <mirrorOf>*</mirrorOf>
      <url>%s/maven/</url>
    </mirror>
  </mirrors>
</settings>
`, stack.HighURL))

	repo := filepath.Join(tmp, "m2repo")
	env := []string{"HOME=" + filepath.Join(tmp, "home")}
	run(t, proj, env, mvn, "-B", "--no-transfer-progress",
		"-s", filepath.Join(tmp, "settings.xml"),
		"-Dmaven.repo.local="+repo,
		"compile")

	jar := filepath.Join(repo, "org", "apache", "commons", "commons-lang3",
		commonsLang3Version, "commons-lang3-"+commonsLang3Version+".jar")
	if _, err := os.Stat(jar); err != nil {
		t.Fatalf("commons-lang3 jar missing from the client's local repo: %v", err)
	}
	classpath := filepath.Join(proj, "target", "classes") + string(os.PathListSeparator) + jar
	out := runStdout(t, proj, nil, javaBin, "-cp", classpath, "e2e.Main")
	if strings.TrimSpace(out) != "aRTIgATE e2e" {
		t.Fatalf("java printed %q, want %q", strings.TrimSpace(out), "aRTIgATE e2e")
	}
}
