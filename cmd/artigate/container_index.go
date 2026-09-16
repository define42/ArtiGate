package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

const containerArtifactIndexVersion = 1

// containerRepoFile extends the historical on-disk repository record without
// changing the signed bundle format. Images retain their discovery associations
// for the dashboard; only ArtifactIndex controls artifact serving and discovery.
type containerRepoFile struct {
	ContainerRepo

	ArtifactIndex *containerArtifactIndex `json:"artifact_index"`
}

// containerArtifactIndex keeps immutable manifest records separately from
// mutable repository tags. Subject in these records is exclusively the native
// subject read from the manifest, never a legacy discovery association.
type containerArtifactIndex struct {
	Version   int                          `json:"version"`
	Artifacts map[string]ContainerArtifact `json:"artifacts"`
	Tags      map[string]string            `json:"tags"`
}

func newContainerArtifactIndex() *containerArtifactIndex {
	return &containerArtifactIndex{
		Version:   containerArtifactIndexVersion,
		Artifacts: make(map[string]ContainerArtifact),
		Tags:      make(map[string]string),
	}
}

// loadContainerRepoIndexLocked upgrades legacy indexes on first use, using the
// already imported manifests. The caller must hold containerIndexMu through
// any subsequent modification and write.
func (s *HighServer) loadContainerRepoIndexLocked(name string) (ContainerRepo, error) {
	b, err := os.ReadFile(s.containerRepoIndexPath(name))
	if err != nil {
		return ContainerRepo{}, err
	}
	var stored containerRepoFile
	if err := json.Unmarshal(b, &stored); err != nil {
		return ContainerRepo{}, err
	}
	repo := stored.ContainerRepo
	repo.artifactIndex = stored.ArtifactIndex
	if repo.artifactIndex != nil {
		if repo.artifactIndex.Version != containerArtifactIndexVersion {
			return ContainerRepo{}, fmt.Errorf("unsupported container artifact index version %d", repo.artifactIndex.Version)
		}
		if repo.artifactIndex.Artifacts == nil || repo.artifactIndex.Tags == nil {
			return ContainerRepo{}, fmt.Errorf("incomplete container artifact index for %s", name)
		}
		return repo, nil
	}
	repo.artifactIndex = newContainerArtifactIndex()
	if err := s.mergeContainerArtifacts(repo.artifactIndex, repo.Images, true); err != nil {
		return ContainerRepo{}, fmt.Errorf("rebuild container artifact index for %s: %w", name, err)
	}
	if err := s.writeContainerRepoIndex(name, repo); err != nil {
		return ContainerRepo{}, err
	}
	return repo, nil
}

func (s *HighServer) writeContainerRepoIndex(name string, repo ContainerRepo) error {
	return writeJSONAtomic(s.containerRepoIndexPath(name), containerRepoFile{
		ContainerRepo: repo, ArtifactIndex: repo.artifactIndex,
	}, 0o644)
}

// mergeContainerArtifacts never interprets absent discovery results as a
// deletion. Each observed tag moves once in the repository namespace, while all
// previous manifests and their blob references remain reachable by digest.
func (s *HighServer) mergeContainerArtifacts(index *containerArtifactIndex, images []ContainerImage, migrating bool) error {
	for _, img := range images {
		for _, record := range img.Artifacts {
			if err := s.mergeContainerArtifact(index, record, migrating); err != nil {
				return err
			}
		}
	}
	return validateStoredContainerGraph(index)
}

func validateStoredContainerGraph(index *containerArtifactIndex) error {
	for _, artifact := range index.Artifacts {
		for _, child := range artifact.Manifests {
			stored, ok := index.Artifacts[child.Digest]
			if !ok || stored.Size != child.Size || stored.MediaType != child.MediaType {
				return fmt.Errorf("artifact index %s has an incomplete child %s", artifact.Digest, child.Digest)
			}
		}
	}
	return nil
}

func (s *HighServer) mergeContainerArtifact(index *containerArtifactIndex, record ContainerArtifact, migrating bool) error {
	if _, known := index.Artifacts[record.Digest]; !known {
		artifact, err := s.storedContainerArtifact(record)
		if err != nil {
			return fmt.Errorf("index artifact %s: %w", record.Digest, err)
		}
		index.Artifacts[record.Digest] = artifact
	}
	if record.Tag == "" {
		return nil
	}
	if previous, exists := index.Tags[record.Tag]; migrating && exists && previous != record.Digest {
		// Old indexes have no observation timestamps. Preserve their
		// first effective mapping until a new collection resolves it.
		log.Printf("containers: conflicting legacy artifact tag %s; retaining %s until refreshed", record.Tag, previous)
		return nil
	}
	index.Tags[record.Tag] = record.Digest
	return nil
}

// storedContainerArtifact derives native discovery metadata from the verified
// manifest bytes. Descriptor annotations and legacy Subject fields must never
// fabricate or overwrite an OCI relationship.
func (s *HighServer) storedContainerArtifact(record ContainerArtifact) (ContainerArtifact, error) {
	if !containerDigestRE.MatchString(record.Digest) {
		return ContainerArtifact{}, fmt.Errorf("invalid manifest digest %q", record.Digest)
	}
	body, err := readFileLimit(s.containerBlobPath(record.Digest), maxServedManifestBytes)
	if err != nil {
		return ContainerArtifact{}, err
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != record.Digest {
		return ContainerArtifact{}, fmt.Errorf("stored manifest digest mismatch")
	}
	var manifest ociManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return ContainerArtifact{}, err
	}
	mediaType := manifest.MediaType
	if mediaType == "" {
		mediaType = record.MediaType
	}
	if !isContainerDocumentType(mediaType) {
		return ContainerArtifact{}, fmt.Errorf("unsupported manifest media type %q", mediaType)
	}
	artifact := ContainerArtifact{
		Digest: record.Digest, MediaType: mediaType, Size: int64(len(body)),
		ArtifactType: containerArtifactType(manifest, nil), Annotations: manifest.Annotations,
	}
	if manifest.Subject != nil && containerDigestRE.MatchString(manifest.Subject.Digest) {
		artifact.Subject = manifest.Subject.Digest
	}
	if isContainerIndexType(mediaType) {
		artifact.ArtifactType = manifest.ArtifactType
		artifact.Manifests, err = storedContainerIndexChildren(manifest.Manifests, record.Manifests)
		return artifact, err
	}
	// Retain only config/layer references actually present in this manifest
	// and authorized by the imported artifact metadata, preserving repository
	// isolation even though the physical blob store is shared.
	descriptors := append([]ociDescriptor{manifest.Config}, manifest.Layers...)
	for _, desc := range descriptors {
		if desc.Digest == "" {
			continue
		}
		if !containerDigestRE.MatchString(desc.Digest) || !containerBlobsInclude(record.Blobs, desc.Digest) {
			return ContainerArtifact{}, fmt.Errorf("unrecorded artifact blob %q", desc.Digest)
		}
		artifact.Blobs = append(artifact.Blobs, ContainerBlob{Digest: desc.Digest, Size: desc.Size})
	}
	return artifact, nil
}

func storedContainerIndexChildren(descriptors []ociDescriptor, authorized []ContainerIndex) ([]ContainerIndex, error) {
	byDigest := make(map[string]ContainerIndex, len(authorized))
	for _, child := range authorized {
		byDigest[child.Digest] = child
	}
	children := make([]ContainerIndex, 0, len(descriptors))
	for _, desc := range descriptors {
		child, ok := byDigest[desc.Digest]
		if !ok || !containerDigestRE.MatchString(desc.Digest) || desc.Size <= 0 ||
			child.Size != desc.Size || child.MediaType != desc.MediaType ||
			(!isContainerManifestType(desc.MediaType) && !isContainerIndexType(desc.MediaType)) {
			return nil, fmt.Errorf("unrecorded or invalid artifact index child %q", desc.Digest)
		}
		children = append(children, child)
	}
	return children, nil
}

// retainContainerArtifacts preserves dashboard associations when a refresh
// discovers fewer attachments. Repository tag resolution uses the independent
// index, so these historical observations cannot restore an old signature tag.
func retainContainerArtifacts(previous, next []ContainerArtifact) []ContainerArtifact {
	merged := append([]ContainerArtifact(nil), previous...)
	positions := make(map[string]int, len(merged))
	for i, artifact := range merged {
		positions[artifact.Digest] = i
	}
	for _, artifact := range next {
		if i, exists := positions[artifact.Digest]; exists {
			merged[i] = artifact
		} else {
			positions[artifact.Digest] = len(merged)
			merged = append(merged, artifact)
		}
	}
	return merged
}
