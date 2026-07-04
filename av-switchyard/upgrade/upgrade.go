package upgrade

import (
    "log"
    "fmt"
    "runtime"
    "os"
    "errors"
    "encoding/json"
    "net/http"
    "sort"
    "strings"

    "av-switchyard/cli"
)

const gh_owner = "Jeffrey-P-McAteer"
const gh_repo = "av-switchyard"

func RunUpgrade(c *cli.CLI) error {
    log.Printf("c.UpgradeVersion = %s", c.UpgradeVersion)
    log.Printf("ComputeBinaryName() = %s", ComputeBinaryName())
    log.Printf("getExecutablePath() = %s", getExecutablePath())

    log.Printf(" // TODO fetch Github release data, compute most-recent, and grab appropriate artifact. ")

    releases, err := fetchReleases(gh_owner, gh_repo)
    if err != nil {
        log.Println("error fetching releases: %v", err)
        return err
    }

    if len(releases) == 0 {
        log.Println("no releases found - are you online?")
        return errors.New("no releases found - are you online?")
    }

    // sort for deterministic behavior
    sortReleases(releases)

    var selected *Release

    if c.UpgradeVersion == "" {
        // default: newest
        selected = &releases[0]
    } else {
        selected = findRelease(releases, c.UpgradeVersion)
        if selected == nil {
            log.Printf("version %q not found. Available releases = %v\n", c.UpgradeVersion, releases)
            return errors.New("requested version not found")
        }
    }

    log.Printf("Selected release: %s", selected.TagName)

    return nil
}

func ComputeBinaryName() string {
    os := runtime.GOOS
    arch := runtime.GOARCH

    // Normalize Go's naming to our labels
    if os == "darwin" {
        os = "macos"
    }

    extension := ""
    if os == "windows" {
        extension = ".exe"
    }

    return fmt.Sprintf("av-switchyard-%s-%s%s", os, arch, extension)
}

func getExecutablePath() string {
    exe_path, err := os.Executable()
    if err != nil {
        computed_exe_path := ComputeBinaryName()
        log.Printf("Cannot determine executable path, falling back to %s - %v", computed_exe_path, err)
        return computed_exe_path
    } else {
        return exe_path
    }
}

// GitHub API response (partial fields we need)
type Release struct {
    TagName string `json:"tag_name"`
}

// fetchReleases queries GitHub API
func fetchReleases(owner, repo string) ([]Release, error) {
    url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", owner, repo)

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    // GitHub recommends a User-Agent
    req.Header.Set("User-Agent", "av-switchyard-upgrader")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("GitHub API error: %s", resp.Status)
    }

    var releases []Release
    if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
        return nil, err
    }

    return releases, nil
}

// normalize version strings (removes leading "v")
func normalize(v string) string {
    return strings.TrimPrefix(v, "v")
}

// simple semver-ish compare (major.minor.patch assumed)
func versionLess(a, b string) bool {
    pa := strings.Split(normalize(a), ".")
    pb := strings.Split(normalize(b), ".")

    for len(pa) < 3 {
        pa = append(pa, "0")
    }
    for len(pb) < 3 {
        pb = append(pb, "0")
    }

    for i := 0; i < 3; i++ {
        if pa[i] != pb[i] {
            return pa[i] < pb[i]
        }
    }
    return false
}

// sort releases newest -> oldest
func sortReleases(rels []Release) {
    sort.Slice(rels, func(i, j int) bool {
        // reverse: newest first
        return versionLess(rels[j].TagName, rels[i].TagName)
    })
}

// find a specific version
func findRelease(rels []Release, target string) *Release {
    target = normalize(target)

    for _, r := range rels {
        if normalize(r.TagName) == target {
            return &r
        }
    }
    return nil
}

