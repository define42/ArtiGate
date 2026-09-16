package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
)

const containerIntegrityRepos = "cache/download/containers/repos"

type containerIntegrityOptions struct {
	Root       string
	Repository string
	Repair     bool
}

type containerIntegrityIssue struct {
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	Repairable bool   `json:"repairable"`
}

type containerIntegrityRepository struct {
	Name     string                    `json:"name"`
	Issues   []containerIntegrityIssue `json:"issues"`
	Repaired bool                      `json:"repaired"`
}

type containerIntegrityReport struct {
	OK           bool                           `json:"ok"`
	Repositories []containerIntegrityRepository `json:"repositories"`
	BlobsChecked int                            `json:"blobs_checked"`
	Repaired     int                            `json:"repaired"`
}

type containerIntegrityBlob struct {
	size int64
	err  error
}

type containerIntegrityChecker struct {
	root     *os.Root
	verified map[string]containerIntegrityBlob
}

type containerIntegrityRepair struct {
	file        string
	fingerprint [sha256.Size]byte
	fields      map[string]json.RawMessage
	index       *containerArtifactIndex
}

// checkContainerIntegrity is offline: it never starts a server, creates a root,
// or invokes the serving path's automatic legacy-index migration. Callers must
// stop the high side before checking or repairing its files.
func checkContainerIntegrity(ctx context.Context, options containerIntegrityOptions) (containerIntegrityReport, error) {
	report := containerIntegrityReport{OK: true, Repositories: []containerIntegrityRepository{}}
	if options.Root == "" {
		return report, errors.New("--root is required")
	}
	root, err := os.OpenRoot(options.Root)
	if err != nil {
		return report, err
	}
	defer root.Close()
	names, err := containerIntegrityRepositoryNames(ctx, root, options.Repository)
	if err != nil {
		return report, err
	}
	checker := containerIntegrityChecker{root: root, verified: make(map[string]containerIntegrityBlob)}
	repairs, err := checker.scanRepositories(ctx, names, options.Repair, &report)
	report.BlobsChecked = len(checker.verified)
	if err != nil {
		return report, err
	}
	if options.Repair && containerIntegrityCanRepair(report.Repositories) {
		if err := checker.applyRepairs(ctx, repairs, &report); err != nil {
			return report, err
		}
	}
	for _, repo := range report.Repositories {
		if len(repo.Issues) != 0 && !repo.Repaired {
			report.OK = false
		}
	}
	return report, ctx.Err()
}

func (c *containerIntegrityChecker) scanRepositories(ctx context.Context, names []string, repair bool, report *containerIntegrityReport) ([]containerIntegrityRepair, error) {
	var plans []containerIntegrityRepair
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, plan := c.checkRepository(ctx, name, false)
		report.Repositories = append(report.Repositories, result)
		if repair {
			plans = append(plans, plan)
		}
	}
	return plans, nil
}

func containerIntegrityRepositoryNames(ctx context.Context, root *os.Root, repository string) ([]string, error) {
	if repository != "" {
		return containerIntegritySelectedRepository(root, repository)
	}
	var names []string
	err := fs.WalkDir(root.FS(), containerIntegrityRepos, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("repository scan refuses symbolic link %s", name)
		}
		if !entry.IsDir() && entry.Name() == "_index.json" {
			names = append(names, strings.TrimPrefix(path.Dir(name), containerIntegrityRepos+"/"))
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) && len(names) == 0 {
		return []string{}, nil
	}
	return names, err
}

func containerIntegritySelectedRepository(root *os.Root, repository string) ([]string, error) {
	if !validContainerName(repository) {
		return nil, fmt.Errorf("invalid repository %q", repository)
	}
	if _, err := root.Stat(path.Join(containerIntegrityRepos, repository, "_index.json")); err != nil {
		return nil, fmt.Errorf("repository %s: %w", repository, err)
	}
	return []string{repository}, nil
}

func (c *containerIntegrityChecker) checkRepository(ctx context.Context, name string, prepareRepair bool) (containerIntegrityRepository, containerIntegrityRepair) {
	result := containerIntegrityRepository{Name: name, Issues: []containerIntegrityIssue{}}
	repair := containerIntegrityRepair{file: path.Join(containerIntegrityRepos, name, "_index.json")}
	stored, err := c.readRepository(ctx, name, &repair, prepareRepair)
	if err != nil {
		result.addIssue("repository_invalid", err, false)
		return result, repair
	}
	records, err := containerIntegrityArtifactRecords(stored)
	if err != nil {
		result.addIssue("index_invalid", err, false)
		return result, repair
	}
	rebuilt := newContainerArtifactIndex()
	for _, digest := range sortedMapKeys(records) {
		artifact, err := c.checkArtifact(ctx, records[digest])
		if err != nil {
			result.addIssue("content_invalid", fmt.Errorf("artifact %s: %w", digest, err), false)
			continue
		}
		rebuilt.Artifacts[digest] = artifact
	}
	for _, img := range stored.Images {
		if err := c.checkImage(ctx, img, rebuilt); err != nil {
			result.addIssue("content_invalid", fmt.Errorf("image %s: %w", img.Digest, err), false)
		}
	}
	if err := validateStoredContainerGraph(rebuilt); err != nil {
		result.addIssue("graph_incomplete", err, false)
	}
	if err := containerIntegrityTags(stored, rebuilt); err != nil {
		result.addIssue("tags_ambiguous", err, false)
	}
	containerIntegrityIndexIssue(stored.ArtifactIndex, rebuilt, &result)
	if prepareRepair {
		repair.index = rebuilt
	}
	return result, repair
}

func (r *containerIntegrityRepository) addIssue(code string, err error, repairable bool) {
	r.Issues = append(r.Issues, containerIntegrityIssue{Code: code, Detail: err.Error(), Repairable: repairable})
}

func (c *containerIntegrityChecker) readRepository(ctx context.Context, name string, repair *containerIntegrityRepair, preserveFields bool) (containerRepoFile, error) {
	var stored containerRepoFile
	if !validContainerName(name) {
		return stored, fmt.Errorf("invalid repository path %q", name)
	}
	stored, fields, fingerprint, err := c.readRepositoryJSON(ctx, repair.file, preserveFields)
	if err != nil {
		return stored, err
	}
	if stored.Registry+"/"+stored.Repository != name {
		return stored, errors.New("repository identity does not match its index path")
	}
	if len(stored.Images) == 0 {
		return stored, errors.New("repository has no image or artifact roots")
	}
	repair.fields = fields
	repair.fingerprint = fingerprint
	return stored, nil
}

// Existing artifact records are the authorization boundary. Never discover
// additional repository membership by scanning the shared content store.
func containerIntegrityArtifactRecords(stored containerRepoFile) (map[string]ContainerArtifact, error) {
	records := make(map[string]ContainerArtifact)
	for _, image := range stored.Images {
		for _, artifact := range image.Artifacts {
			if err := containerIntegrityAddRecord(records, artifact); err != nil {
				return nil, err
			}
		}
	}
	if stored.ArtifactIndex == nil {
		return records, nil
	}
	if stored.ArtifactIndex.Version != containerArtifactIndexVersion {
		return nil, fmt.Errorf("unsupported artifact index version %d", stored.ArtifactIndex.Version)
	}
	if stored.ArtifactIndex.Tags == nil || stored.ArtifactIndex.Artifacts == nil {
		return nil, errors.New("artifact membership or tag mappings are missing; history and mutable aliases cannot be reconstructed safely")
	}
	for digest, artifact := range stored.ArtifactIndex.Artifacts {
		if digest != artifact.Digest {
			return nil, fmt.Errorf("artifact index key %s disagrees with record digest %s", digest, artifact.Digest)
		}
		if err := containerIntegrityAddRecord(records, artifact); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func containerIntegrityAddRecord(records map[string]ContainerArtifact, artifact ContainerArtifact) error {
	if !containerDigestRE.MatchString(artifact.Digest) {
		return fmt.Errorf("invalid artifact digest %q", artifact.Digest)
	}
	previous, exists := records[artifact.Digest]
	if !exists {
		records[artifact.Digest] = artifact
		return nil
	}
	if previous.MediaType != artifact.MediaType || previous.Size != artifact.Size {
		return fmt.Errorf("conflicting identity metadata for artifact %s", artifact.Digest)
	}
	previous.Blobs = append(previous.Blobs, artifact.Blobs...)
	previous.Manifests = append(previous.Manifests, artifact.Manifests...)
	records[artifact.Digest] = previous
	return nil
}

func containerIntegrityTags(stored containerRepoFile, rebuilt *containerArtifactIndex) error {
	if err := containerIntegrityImageTags(stored.Images); err != nil {
		return err
	}
	if stored.ArtifactIndex == nil {
		return containerIntegrityLegacyTags(stored.Images, rebuilt.Tags)
	}
	for tag, digest := range stored.ArtifactIndex.Tags {
		if _, exists := rebuilt.Artifacts[digest]; !exists {
			return fmt.Errorf("tag %q references an unavailable artifact %s", tag, digest)
		}
		if tag == "" {
			return errors.New("empty artifact tag mapping")
		}
		if err := containerIntegritySetTag(rebuilt.Tags, tag, digest); err != nil {
			return err
		}
	}
	return nil
}

func containerIntegrityImageTags(images []ContainerImage) error {
	imageTags := make(map[string]string)
	for _, image := range images {
		digest := image.Digest
		if image.Index != nil {
			digest = image.Index.Digest
		}
		if err := containerIntegritySetTag(imageTags, image.Tag, digest); err != nil {
			return err
		}
	}
	return nil
}

func containerIntegrityLegacyTags(images []ContainerImage, tags map[string]string) error {
	for _, image := range images {
		for _, artifact := range image.Artifacts {
			if err := containerIntegritySetTag(tags, artifact.Tag, artifact.Digest); err != nil {
				return err
			}
		}
	}
	return nil
}

func containerIntegritySetTag(tags map[string]string, tag, digest string) error {
	if tag == "" {
		return nil
	}
	if !containerTagRE.MatchString(tag) || !containerDigestRE.MatchString(digest) {
		return fmt.Errorf("invalid tag mapping %q to %q", tag, digest)
	}
	if previous, exists := tags[tag]; exists && previous != digest {
		return fmt.Errorf("ambiguous tag %q references both %s and %s", tag, previous, digest)
	}
	tags[tag] = digest
	return nil
}

func containerIntegrityIndexIssue(previous, rebuilt *containerArtifactIndex, result *containerIntegrityRepository) {
	if previous == nil {
		result.addIssue("index_missing", errors.New("legacy repository has no derived artifact index"), true)
		return
	}
	if previous.Version != rebuilt.Version || !maps.Equal(previous.Tags, rebuilt.Tags) ||
		!maps.EqualFunc(previous.Artifacts, rebuilt.Artifacts, containerIntegrityArtifactsEqual) {
		result.addIssue("index_inconsistent", errors.New("derived artifact index differs from verified manifest metadata"), true)
	}
}

func containerIntegrityArtifactsEqual(a, b ContainerArtifact) bool {
	return a.Subject == b.Subject && a.Tag == b.Tag && a.Digest == b.Digest &&
		a.MediaType == b.MediaType && a.ArtifactType == b.ArtifactType && a.Size == b.Size &&
		maps.Equal(a.Annotations, b.Annotations) && slices.Equal(a.Blobs, b.Blobs) && slices.Equal(a.Manifests, b.Manifests)
}

func (c *containerIntegrityChecker) checkArtifact(ctx context.Context, record ContainerArtifact) (ContainerArtifact, error) {
	manifest, err := c.readManifest(ctx, ContainerIndex{Digest: record.Digest, MediaType: record.MediaType, Size: record.Size})
	if err != nil {
		return ContainerArtifact{}, err
	}
	artifact := ContainerArtifact{
		Digest: record.Digest, MediaType: record.MediaType, Size: record.Size,
		ArtifactType: containerArtifactType(manifest, nil), Annotations: manifest.Annotations,
	}
	if manifest.Subject != nil {
		artifact.Subject = manifest.Subject.Digest
	}
	if isContainerIndexType(record.MediaType) {
		if err := c.checkRecordedBlobs(ctx, record.Blobs); err != nil {
			return artifact, err
		}
		artifact.ArtifactType = manifest.ArtifactType
		artifact.Manifests, err = storedContainerIndexChildren(manifest.Manifests, record.Manifests)
		return artifact, err
	}
	artifact.Blobs, err = c.checkManifestBlobs(ctx, manifest, record.Blobs)
	return artifact, err
}

func (c *containerIntegrityChecker) checkImage(ctx context.Context, image ContainerImage, artifacts *containerArtifactIndex) error {
	manifest, err := c.readManifest(ctx, ContainerIndex{Digest: image.Digest, MediaType: image.MediaType, Size: image.Size})
	if err != nil {
		return err
	}
	if isContainerIndexType(image.MediaType) {
		if len(image.Blobs) != 0 {
			return errors.New("artifact index image authorizes payload blobs absent from its manifest")
		}
		if _, exists := artifacts.Artifacts[image.Digest]; !exists {
			return errors.New("artifact index image has no authorized child graph")
		}
	} else if err := c.checkImageBlobs(ctx, manifest, image.Blobs); err != nil {
		return err
	}
	if image.Index == nil {
		return nil
	}
	index, err := c.readManifest(ctx, *image.Index)
	if err != nil {
		return err
	}
	if !isContainerIndexType(image.Index.MediaType) {
		return errors.New("preserved image index has a non-index media type")
	}
	for _, descriptor := range index.Manifests {
		if descriptor.Digest == image.Digest && descriptor.Size == image.Size && descriptor.MediaType == image.MediaType {
			return nil // Other platforms are intentionally not required locally.
		}
	}
	return errors.New("preserved image index does not describe its selected image")
}

func (c *containerIntegrityChecker) checkImageBlobs(ctx context.Context, manifest ociManifest, recorded []ContainerBlob) error {
	canonical, err := c.checkManifestBlobs(ctx, manifest, recorded)
	if err != nil {
		return err
	}
	for _, blob := range recorded {
		if !containerBlobsInclude(canonical, blob.Digest) {
			return fmt.Errorf("image authorizes blob %s absent from its manifest", blob.Digest)
		}
	}
	return nil
}

func (c *containerIntegrityChecker) checkManifestBlobs(ctx context.Context, manifest ociManifest, authorized []ContainerBlob) ([]ContainerBlob, error) {
	if manifest.Config.Digest == "" {
		return nil, errors.New("manifest has no config descriptor")
	}
	var failures []error
	if err := c.checkRecordedBlobs(ctx, authorized); err != nil {
		failures = append(failures, err)
	}
	blobs := make([]ContainerBlob, 0, 1+len(manifest.Layers))
	for _, descriptor := range append([]ociDescriptor{manifest.Config}, manifest.Layers...) {
		if !containerBlobsInclude(authorized, descriptor.Digest) {
			failures = append(failures, fmt.Errorf("manifest references unauthorized blob %q", descriptor.Digest))
			continue
		}
		blob := ContainerBlob{Digest: descriptor.Digest, Size: descriptor.Size}
		if err := c.checkBlob(ctx, blob); err != nil {
			failures = append(failures, err)
		}
		blobs = append(blobs, blob)
	}
	return blobs, errors.Join(failures...)
}

func (c *containerIntegrityChecker) checkRecordedBlobs(ctx context.Context, blobs []ContainerBlob) error {
	var failures []error
	for _, blob := range blobs {
		if err := c.checkBlob(ctx, blob); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (c *containerIntegrityChecker) readManifest(ctx context.Context, record ContainerIndex) (ociManifest, error) {
	var document struct {
		ociManifest

		SchemaVersion int `json:"schemaVersion"`
	}
	if !isContainerDocumentType(record.MediaType) || record.Size <= 0 || record.Size > maxServedManifestBytes {
		return document.ociManifest, errors.New("invalid manifest media type or size")
	}
	if err := c.checkBlob(ctx, ContainerBlob{Digest: record.Digest, Size: record.Size}); err != nil {
		return document.ociManifest, err
	}
	body, err := c.readRegularFile(path.Join("cache/download", containerBlobRel(record.Digest)), maxServedManifestBytes)
	if err != nil {
		return document.ociManifest, err
	}
	// A repair's second pass parses manifests again. Verify these exact bytes
	// even when the blob's earlier streaming hash is in the scan cache.
	sum := sha256.Sum256(body)
	if int64(len(body)) != record.Size || "sha256:"+hex.EncodeToString(sum[:]) != record.Digest {
		return document.ociManifest, errors.New("manifest changed after its content check")
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return document.ociManifest, err
	}
	if document.SchemaVersion != 2 || (document.MediaType != "" && document.MediaType != record.MediaType) {
		return document.ociManifest, errors.New("manifest schema version or media type does not match its record")
	}
	if document.Subject != nil && (!containerDigestRE.MatchString(document.Subject.Digest) || document.Subject.Size < 0) {
		return document.ociManifest, errors.New("invalid native subject descriptor")
	}
	return document.ociManifest, nil
}

func (c *containerIntegrityChecker) checkBlob(ctx context.Context, blob ContainerBlob) error {
	if !containerDigestRE.MatchString(blob.Digest) || blob.Size < 0 {
		return fmt.Errorf("invalid blob descriptor %q (size %d)", blob.Digest, blob.Size)
	}
	verified, exists := c.verified[blob.Digest]
	if !exists {
		verified.size, verified.err = c.hashBlob(ctx, blob.Digest)
		c.verified[blob.Digest] = verified
	}
	if verified.err != nil {
		return fmt.Errorf("blob %s: %w", blob.Digest, verified.err)
	}
	if verified.size != blob.Size {
		return fmt.Errorf("blob %s size %d does not match recorded %d", blob.Digest, verified.size, blob.Size)
	}
	return nil
}

func (c *containerIntegrityChecker) hashBlob(ctx context.Context, digest string) (int64, error) {
	f, err := c.openRegularFile(path.Join("cache/download", containerBlobRel(digest)))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	hash := sha256.New()
	var size int64
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return size, err
		}
		n, err := f.Read(buffer)
		_, _ = hash.Write(buffer[:n])
		size += int64(n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return size, err
		}
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		return size, errors.New("SHA-256 digest mismatch")
	}
	return size, nil
}

func (c *containerIntegrityChecker) openRegularFile(name string) (*os.File, error) {
	info, err := c.root.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return c.root.Open(name)
}

func (c *containerIntegrityChecker) readRegularFile(name string, limit int64) ([]byte, error) {
	f, err := c.openRegularFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(body)) > limit {
		err = fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return body, err
}

func containerIntegrityCanRepair(repositories []containerIntegrityRepository) bool {
	for _, repository := range repositories {
		for _, issue := range repository.Issues {
			if !issue.Repairable {
				return false
			}
		}
	}
	return true
}

func (c *containerIntegrityChecker) applyRepairs(ctx context.Context, repairs []containerIntegrityRepair, report *containerIntegrityReport) error {
	if err := c.checkRepairSources(ctx, repairs); err != nil {
		return err
	}
	for i, repair := range repairs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(report.Repositories[i].Issues) == 0 {
			continue
		}
		prepared, err := c.prepareRepair(ctx, report.Repositories[i].Name, repair)
		if err != nil {
			return err
		}
		if err := c.applyRepair(prepared); err != nil {
			return err
		}
		report.Repositories[i].Repaired = true
		report.Repaired++
	}
	return nil
}

func (c *containerIntegrityChecker) prepareRepair(ctx context.Context, name string, plan containerIntegrityRepair) (containerIntegrityRepair, error) {
	result, prepared := c.checkRepository(ctx, name, true)
	if err := ctx.Err(); err != nil {
		return prepared, err
	}
	if prepared.fingerprint != plan.fingerprint {
		return prepared, containerIntegritySourceChanged(plan.file)
	}
	if !containerIntegrityCanRepair([]containerIntegrityRepository{result}) {
		return prepared, fmt.Errorf("repository no longer passes repair validation: %s", plan.file)
	}
	return prepared, nil
}

func (c *containerIntegrityChecker) checkRepairSources(ctx context.Context, repairs []containerIntegrityRepair) error {
	// Check every source before the first write. This detects an accidentally
	// running importer; stopping the high side remains required for the check.
	for _, repair := range repairs {
		current, err := c.repositoryFingerprint(ctx, repair.file)
		if err != nil {
			return err
		}
		if current != repair.fingerprint {
			return containerIntegritySourceChanged(repair.file)
		}
	}
	return nil
}

func containerIntegritySourceChanged(file string) error {
	return fmt.Errorf("repository changed during check: %s; stop the high side before repair", file)
}

func (c *containerIntegrityChecker) applyRepair(repair containerIntegrityRepair) error {
	index, err := json.Marshal(repair.index)
	if err != nil {
		return err
	}
	repair.fields["artifact_index"] = index
	body, err := json.MarshalIndent(repair.fields, "", "  ")
	if err != nil {
		return err
	}
	return c.replaceIndex(repair.file, append(body, '\n'))
}

func (c *containerIntegrityChecker) replaceIndex(name string, body []byte) error {
	info, err := c.root.Stat(name)
	if err != nil {
		return err
	}
	temporary := name + ".repair-" + rand.Text()
	f, err := c.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = c.root.Remove(temporary)
	}()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := c.root.Rename(temporary, name); err != nil {
		return err
	}
	if directory, err := c.root.Open(path.Dir(name)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
