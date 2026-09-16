package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
)

// Required index children are bounded separately from optional referrers.
// The count/fetch limits also apply across the entire collected graph.
const containerMaxArtifactDepth = 16

func isContainerDocumentType(mediaType string) bool {
	return isContainerManifestType(mediaType) || isContainerIndexType(mediaType)
}

// isContainerArtifactDocument separates runnable images from opaque artifacts.
// Image configs still undergo platform validation; arbitrary artifact configs
// are content-addressed payloads and need not contain JSON.
func isContainerArtifactDocument(m ociManifest, mediaType string) bool {
	if isContainerIndexType(mediaType) {
		if m.Config.Digest != "" || len(m.Layers) != 0 {
			return false
		}
		if m.ArtifactType != "" || m.Subject != nil {
			return true
		}
		for _, child := range m.Manifests {
			if child.Platform != nil {
				return false
			}
		}
		return true
	}
	if m.Config.MediaType == "application/vnd.oci.image.config.v1+json" ||
		m.Config.MediaType == "application/vnd.docker.container.image.v1+json" {
		return false
	}
	return m.ArtifactType != "" || m.Config.MediaType != ""
}

func (c *containerClient) mirrorContainerArtifact(ctx context.Context, ref imageRef, resolved resolvedImage, stageRoot string, seen map[string]bool) (ContainerImage, []ManifestFile, error) {
	col := &artifactCollector{
		c: c, ref: ref, stageRoot: stageRoot, seenFile: seen,
		found: make(map[string]*ContainerArtifact), skip: make(map[string]bool),
	}
	if err := col.collectGraph(ctx, "", "", resolved.Manifest, resolved.MediaType, resolved.Digest, nil, false); err != nil {
		return ContainerImage{}, nil, fmt.Errorf("%s: collect artifact: %w", ref, err)
	}
	root := col.found[resolved.Digest]
	img := ContainerImage{
		Tag: ref.Tag, Digest: root.Digest, MediaType: root.MediaType, Size: root.Size,
		Blobs: root.Blobs,
	}
	var err error
	col.files, err = stageResolvedIndex(&img, resolved, stageRoot, seen, col.files)
	if err != nil {
		return ContainerImage{}, nil, err
	}
	if resolved.IndexDigest != "" {
		col.skip[resolved.IndexDigest] = true
	}
	col.discover(ctx, artifactSubjects(resolved))
	img.Artifacts = col.list()
	return img, col.files, nil
}

// A runnable image can itself carry a native subject. Its platform has already
// been validated and its blobs staged; retain the relationship without changing
// image selection or downloading any content again.
func (a *artifactCollector) seedImageSubject(ctx context.Context, resolved resolvedImage) {
	var manifest ociManifest
	if json.Unmarshal(resolved.Manifest, &manifest) != nil || manifest.Subject == nil {
		return
	}
	if err := a.collectGraph(ctx, "", "", resolved.Manifest, resolved.MediaType, resolved.Digest, nil, false); err != nil {
		noteContainerDiscoveryIssue(ctx, "artifact_invalid", resolved.Digest)
		emitProgress(ctx, "    ⚠ image subject %s: %v", shortDigest(resolved.Digest), err)
	}
}

// discover walks optional attachment relationships breadth first. Required
// index children are already complete when their digests enter a.order.
func (a *artifactCollector) discover(ctx context.Context, subjects []string) {
	visited := make(map[string]bool)
	for _, subject := range subjects {
		a.discoverSubject(ctx, subject, visited)
	}
	for next := 0; next < len(a.order) && !a.capReached(ctx); next++ {
		a.discoverSubject(ctx, a.order[next], visited)
	}
}

func (a *artifactCollector) discoverSubject(ctx context.Context, subject string, visited map[string]bool) {
	if visited[subject] || ctx.Err() != nil || a.capReached(ctx) {
		return
	}
	visited[subject] = true
	noteContainerDiscoverySubject(ctx, subject)
	for _, suffix := range []string{".sig", ".att", ".sbom"} {
		a.addByTag(ctx, subject, cosignArtifactTag(subject, suffix))
	}
	if a.capReached(ctx) {
		return
	}
	for _, desc := range a.c.fetchReferrers(ctx, a.ref, subject) {
		a.addReferrer(ctx, subject, desc)
		if a.capReached(ctx) {
			break
		}
	}
}

// containerArtifactGraph stages a required manifest closure before committing
// any record to discovery or the signed bundle. A missing child rejects this
// graph, leaving previously successful attachments untouched.
type containerArtifactGraph struct {
	collector *artifactCollector
	stager    artifactCollector
	pending   map[string]*ContainerArtifact
	visiting  map[string]bool
	order     []string
	files     []ManifestFile
}

func (a *artifactCollector) collectGraph(ctx context.Context, subject, tag string, body []byte, mediaType, digest string, desc *ociDescriptor, requireSubject bool) error {
	g := &containerArtifactGraph{
		collector: a, stager: *a,
		pending: make(map[string]*ContainerArtifact), visiting: make(map[string]bool),
	}
	g.stager.seenFile = maps.Clone(a.seenFile)
	if g.stager.seenFile == nil {
		g.stager.seenFile = make(map[string]bool)
	}
	if err := g.stage(ctx, subject, tag, body, mediaType, digest, desc, requireSubject, 0); err != nil {
		return err
	}
	for _, key := range g.order {
		a.found[key] = g.pending[key]
		a.order = append(a.order, key)
	}
	a.files = append(a.files, g.files...)
	if a.seenFile == nil {
		a.seenFile = make(map[string]bool)
	}
	maps.Copy(a.seenFile, g.stager.seenFile)
	return nil
}

func (g *containerArtifactGraph) stage(ctx context.Context, subject, tag string, body []byte, mediaType, digest string, desc *ociDescriptor, requireSubject bool, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.visiting[digest] {
		return errors.New("artifact index contains a cycle")
	}
	if g.pending[digest] != nil || g.collector.found[digest] != nil {
		return nil
	}
	if depth > containerMaxArtifactDepth || len(g.pending)+len(g.collector.found) >= containerMaxImageArtifacts {
		g.collector.warnCapped(ctx)
		return &containerArtifactLimitError{}
	}
	art, files, err := g.stager.stageArtifact(ctx, subject, tag, body, mediaType, digest, desc, requireSubject)
	if err != nil {
		return err
	}
	g.pending[digest], g.visiting[digest] = &art, true
	// File order follows staging order: the first occurrence carries Prior
	// when a shared blob was already exported; later references reuse it.
	g.files = append(g.files, files...)
	for _, child := range art.Manifests {
		if err := g.stageChild(ctx, child, depth+1); err != nil {
			return fmt.Errorf("artifact index %s child %s: %w", shortDigest(digest), shortDigest(child.Digest), err)
		}
	}
	delete(g.visiting, digest)
	g.order = append(g.order, digest)
	return nil
}

func (g *containerArtifactGraph) stageChild(ctx context.Context, child ContainerIndex, depth int) error {
	if g.visiting[child.Digest] {
		return errors.New("artifact index contains a cycle")
	}
	known := g.pending[child.Digest]
	if known == nil {
		known = g.collector.found[child.Digest]
	}
	if known != nil {
		if known.Size != child.Size || known.MediaType != child.MediaType {
			return errors.New("artifact child descriptor does not match stored manifest")
		}
		return nil
	}
	if depth > containerMaxArtifactDepth || g.collector.capReached(ctx) || len(g.pending)+len(g.collector.found) >= containerMaxImageArtifacts {
		g.collector.warnCapped(ctx)
		return &containerArtifactLimitError{}
	}
	g.collector.attempts++
	body, mediaType, digest, found, err := g.collector.c.fetchArtifactManifest(ctx, g.collector.ref, child.Digest)
	if err != nil {
		return &containerArtifactFetchError{cause: err}
	}
	if !found {
		return &containerArtifactFetchError{cause: errors.New("required manifest missing upstream")}
	}
	if int64(len(body)) != child.Size || mediaType != child.MediaType {
		return errors.New("artifact child descriptor does not match fetched manifest")
	}
	return g.stage(ctx, "", "", body, mediaType, digest, nil, false, depth)
}

func (a *artifactCollector) stageArtifactContent(ctx context.Context, m ociManifest, mediaType string) ([]ContainerBlob, []ContainerIndex, []ManifestFile, error) {
	if !isContainerIndexType(mediaType) {
		blobs, files, err := a.c.downloadArtifactBlobs(ctx, a.ref, m, a.stageRoot, a.seenFile)
		return blobs, nil, files, err
	}
	children := make([]ContainerIndex, 0, len(m.Manifests))
	for _, desc := range m.Manifests {
		if !containerDigestRE.MatchString(desc.Digest) || desc.Size <= 0 ||
			(!isContainerManifestType(desc.MediaType) && !isContainerIndexType(desc.MediaType)) {
			return nil, nil, nil, fmt.Errorf("invalid artifact index child %q", desc.Digest)
		}
		children = append(children, ContainerIndex{Digest: desc.Digest, MediaType: desc.MediaType, Size: desc.Size})
	}
	return nil, children, nil, nil
}
