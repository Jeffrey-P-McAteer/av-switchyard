package upgrade

/*

Note: This is currently a _mess_ as I've been scraping together cross-platform designs to do
      the entire atomic-file-swap cleanly. Windorks is the worst, and we will likely just shell
      out to powershell to watch our PID exit, then rename the new file to the current one.

      See RunUpgrade() for the high-level logic, everything beneath is a mess of utility and partial task functions.

*/

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
//    "path/filepath"
    "io"
    "archive/zip"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "strconv"

    "github.com/minio/selfupdate"

    "av-switchyard/cli"
)

const gh_owner = "Jeffrey-P-McAteer"
const gh_repo = "av-switchyard"

func RunUpgrade(c *cli.CLI) error {

    releases, err := fetchReleases(gh_owner, gh_repo)
    if err != nil {
        log.Printf("error fetching releases: %v\n", err)
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
            log.Printf("version %q not found. Available releases = %v\n", c.UpgradeVersion, ComputeAvailableVersionsString(releases) )
            return errors.New("requested version not found")
        }
    }

    log.Printf("Selected release: %s", selected.TagName)

    asset, err := findAsset(selected)
    if err != nil {
        log.Printf("Asset %q not found. %v\n", selected.TagName, err)
        return errors.New("Asset for this OS could not be found")
    }

    log.Printf("Downloading: %s from %s", asset.Name, asset.URL)

    data, err := download(asset.URL)
    if err != nil {
        log.Printf("Error downloading: %s - %v\n", asset.URL, err)
        return errors.New("Error downloading asset")
    }

    var update_payload []byte

    if strings.HasSuffix(asset.Name, ".zip") {
        files, err := extractZipInMemory(data)
        if err != nil {
            log.Printf("Error extracting zip in-memory: %v\n", err)
            return errors.New("Error extracting zip in-memory")
        }

        // assume single binary inside zip
        for _, v := range files {
            update_payload = v
            break
        }
    } else {
        update_payload = data
    }

    log.Printf("Downloaded binary size %.3f MB", float64(len(update_payload)) / 1_000_000 )
    log.Printf("Binary %s version %s has sha256 hash %s", ComputeBinaryName(), selected.TagName, SHA256Lower(update_payload) )

    exe := getExecutablePath()

    log.Printf("Replacing: %s", exe)

    update_payload_reader := bytes.NewReader(update_payload)
    err2 := selfupdate.Apply(update_payload_reader, selfupdate.Options{ TargetPath: exe })
    if err2 != nil {
        log.Printf("Error self-updating: %v\n", err2)
        return err2
    }

    return nil
}

func SHA256Lower(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

func ComputeAvailableVersionsString(releases []Release) string {
    if len(releases) == 0 {
        return ""
    }
    names := make([]string, 0, len(releases))
    for _, r := range releases {
        if r.TagName != "" {
            names = append(names, r.TagName)
        }
    }

    return strings.Join(names, ", ")
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

// normalize version strings (removes leading "v")
func normalize(v string) string {
    return strings.TrimPrefix(v, "v")
}

func versionLess(a, b string) bool {
    aa := normalizeVersion(a)
    bb := normalizeVersion(b)

    maxLen := len(aa)
    if len(bb) > maxLen {
        maxLen = len(bb)
    }

    for i := 0; i < maxLen; i++ {
        var ai, bi int

        if i < len(aa) {
            ai = aa[i]
        }
        if i < len(bb) {
            bi = bb[i]
        }

        if ai < bi {
            return true
        }
        if ai > bi {
            return false
        }
    }

    return false // equal
}

func normalizeVersion(v string) []int {
    v = strings.TrimPrefix(v, "v")
    parts := strings.Split(v, ".")

    out := make([]int, 0, len(parts))
    for _, p := range parts {
        n, err := strconv.Atoi(p)
        if err != nil {
            n = 0 // fallback for malformed segments
        }
        out = append(out, n)
    }
    return out
}


// GitHub API response (partial fields we need)
type Release struct {
    TagName string `json:"tag_name"`
    Assets  []Asset `json:"assets"`
}

type Asset struct {
    Name string `json:"name"`
    URL  string `json:"browser_download_url"`
}

func fetchReleases(owner, repo string) ([]Release, error) {
    url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", owner, repo)

    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", "av-switchyard-updater")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var rels []Release
    err = json.NewDecoder(resp.Body).Decode(&rels)
    return rels, err
}

func ghAssetRuntimeComponent() string {
    os := runtime.GOOS
    if os == "darwin" {
        os = "macos"
    }
    ext := ""
    if os == "windows" {
        ext = ".zip"
    }
    return os + "-" + runtime.GOARCH + ext
}

func findAsset(r *Release) (*Asset, error) {
    target := ghAssetRuntimeComponent()

    for _, a := range r.Assets {
        name := strings.ToLower(a.Name)
        if strings.Contains(name, target) {
            return &a, nil
        }
    }
    return nil, fmt.Errorf("no matching asset, searched for %s", target)
}

func download(url string) ([]byte, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    return io.ReadAll(resp.Body)
}

// -------------------- ZIP IN MEMORY --------------------

func extractZipInMemory(data []byte) (map[string][]byte, error) {
    files := make(map[string][]byte)

    r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return nil, err
    }

    for _, f := range r.File {
        rc, err := f.Open()
        if err != nil {
            return nil, err
        }

        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            return nil, err
        }

        if !f.FileInfo().IsDir() {
            files[f.Name] = content
        }
    }

    return files, nil
}

func atomicReplace(newBytes []byte, targetPath string) error {
    tmp := targetPath + ".new"

    if err := os.WriteFile(tmp, newBytes, 0755); err != nil {
        return err
    }

    // Windows-safe rename
    return replaceFile(tmp, targetPath)
}

// -------------------- PLATFORM SAFE RENAME --------------------

func replaceFile(src, dst string) error {
    // Windows
    if runtime.GOOS == "windows" {
        return windowsReplace(src, dst)
    }

    // Unix (atomic rename)
    return os.Rename(src, dst)
}

func windowsReplace(src, dst string) error {
    // Use syscall MoveFileExW for overwrite semantics
    // (avoids "file in use" issues as much as Windows allows)
    //return moveFileEx(src, dst)
    panic(errors.New("windowsReplace unimplemented"))
    return errors.New("can never occur")
}

