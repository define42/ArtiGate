package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Repository indexes have no size cap on import or serving. Decode their
// collections one record at a time instead of buffering the whole JSON value.
// Raw metadata is retained only while preparing one explicitly requested repair.
func (c *containerIntegrityChecker) readRepositoryJSON(ctx context.Context, file string, preserveFields bool) (containerRepoFile, map[string]json.RawMessage, [sha256.Size]byte, error) {
	var stored containerRepoFile
	var fingerprint [sha256.Size]byte
	f, err := c.openRegularFile(file)
	if err != nil {
		return stored, nil, fingerprint, err
	}
	defer f.Close()
	hash := sha256.New()
	reader := bufio.NewReaderSize(containerIntegrityReader{ctx: ctx, reader: f}, 64<<10)
	decoder := json.NewDecoder(io.TeeReader(reader, hash))
	decoder.UseNumber()
	fields, err := decodeContainerIntegrityRepository(decoder, &stored, preserveFields)
	if err == nil {
		err = finishContainerIntegrityJSON(decoder)
	}
	copy(fingerprint[:], hash.Sum(nil))
	return stored, fields, fingerprint, err
}

func decodeContainerIntegrityRepository(decoder *json.Decoder, stored *containerRepoFile, preserveFields bool) (map[string]json.RawMessage, error) {
	if _, err := beginContainerIntegrityJSON(decoder, '{', false); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if preserveFields {
		fields = make(map[string]json.RawMessage)
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := containerIntegrityUniqueJSONKey(decoder, seen)
		if err != nil {
			return nil, err
		}
		fieldDecoder := decoder
		if preserveFields {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return nil, err
			}
			fields[key] = raw
			fieldDecoder = json.NewDecoder(bytes.NewReader(raw))
			fieldDecoder.UseNumber()
		}
		if err := decodeContainerIntegrityField(fieldDecoder, key, stored); err != nil {
			return nil, err
		}
	}
	return fields, endContainerIntegrityJSON(decoder, '}')
}

func decodeContainerIntegrityField(decoder *json.Decoder, key string, stored *containerRepoFile) error {
	switch key {
	case "registry":
		return decoder.Decode(&stored.Registry)
	case "repository":
		return decoder.Decode(&stored.Repository)
	case "images":
		return decodeContainerIntegrityImages(decoder, stored)
	case "artifact_index":
		index, err := decodeContainerIntegrityIndex(decoder)
		stored.ArtifactIndex = index
		return err
	default:
		return skipContainerIntegrityJSON(decoder)
	}
}

func decodeContainerIntegrityImages(decoder *json.Decoder, stored *containerRepoFile) error {
	null, err := beginContainerIntegrityJSON(decoder, '[', true)
	stored.Images = nil
	if err != nil || null {
		return err
	}
	for decoder.More() {
		var image ContainerImage
		if err := decoder.Decode(&image); err != nil {
			return err
		}
		stored.Images = append(stored.Images, image)
	}
	return endContainerIntegrityJSON(decoder, ']')
}

func decodeContainerIntegrityIndex(decoder *json.Decoder) (*containerArtifactIndex, error) {
	null, err := beginContainerIntegrityJSON(decoder, '{', true)
	if err != nil || null {
		return nil, err
	}
	index := new(containerArtifactIndex)
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := containerIntegrityUniqueJSONKey(decoder, seen)
		if err != nil {
			return nil, err
		}
		switch key {
		case "version":
			err = decoder.Decode(&index.Version)
		case "tags":
			index.Tags, err = decodeContainerIntegrityTags(decoder)
		case "artifacts":
			index.Artifacts, err = decodeContainerIntegrityArtifacts(decoder)
		default:
			err = fmt.Errorf("artifact index contains unsupported field %q that repair must preserve", key)
		}
		if err != nil {
			return nil, err
		}
	}
	return index, endContainerIntegrityJSON(decoder, '}')
}

func decodeContainerIntegrityArtifacts(decoder *json.Decoder) (map[string]ContainerArtifact, error) {
	null, err := beginContainerIntegrityJSON(decoder, '{', true)
	if err != nil || null {
		return nil, err
	}
	artifacts := make(map[string]ContainerArtifact)
	for decoder.More() {
		digest, err := containerIntegrityJSONKey(decoder)
		if err != nil {
			return nil, err
		}
		if _, exists := artifacts[digest]; exists {
			return nil, fmt.Errorf("duplicate artifact digest key %q", digest)
		}
		var artifact containerIntegrityStrictArtifact
		if err := decoder.Decode(&artifact); err != nil {
			return nil, fmt.Errorf("artifact index metadata: %w", err)
		}
		artifacts[digest] = ContainerArtifact(artifact)
	}
	return artifacts, endContainerIntegrityJSON(decoder, '}')
}

func decodeContainerIntegrityTags(decoder *json.Decoder) (map[string]string, error) {
	null, err := beginContainerIntegrityJSON(decoder, '{', true)
	if err != nil || null {
		return nil, err
	}
	tags := make(map[string]string)
	for decoder.More() {
		tag, err := containerIntegrityJSONKey(decoder)
		if err != nil {
			return nil, err
		}
		if _, exists := tags[tag]; exists {
			return nil, fmt.Errorf("duplicate artifact tag key %q", tag)
		}
		var digest string
		if err := decoder.Decode(&digest); err != nil {
			return nil, err
		}
		tags[tag] = digest
	}
	return tags, endContainerIntegrityJSON(decoder, '}')
}

type containerIntegrityStrictArtifact ContainerArtifact

func (artifact *containerIntegrityStrictArtifact) UnmarshalJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*ContainerArtifact)(artifact))
}

func beginContainerIntegrityJSON(decoder *json.Decoder, delimiter json.Delim, allowNull bool) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if token == nil && allowNull {
		return true, nil
	}
	if token != delimiter {
		return false, fmt.Errorf("expected JSON delimiter %q", delimiter)
	}
	return false, nil
}

func endContainerIntegrityJSON(decoder *json.Decoder, delimiter json.Delim) error {
	_, err := beginContainerIntegrityJSON(decoder, delimiter, false)
	return err
}

func containerIntegrityJSONKey(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", errors.New("expected JSON object key")
	}
	return key, nil
}

func containerIntegrityUniqueJSONKey(decoder *json.Decoder, seen map[string]bool) (string, error) {
	key, err := containerIntegrityJSONKey(decoder)
	if err != nil {
		return "", err
	}
	if seen[key] {
		return "", fmt.Errorf("duplicate repository metadata key %q", key)
	}
	seen[key] = true
	return key, nil
}

func skipContainerIntegrityJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') && token != json.Delim('[') {
		return nil
	}
	for depth := 1; depth > 0; {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

func finishContainerIntegrityJSON(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected data after repository JSON")
}

type containerIntegrityReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r containerIntegrityReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (c *containerIntegrityChecker) repositoryFingerprint(ctx context.Context, file string) ([sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	f, err := c.openRegularFile(file)
	if err != nil {
		return fingerprint, err
	}
	defer f.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, containerIntegrityReader{ctx: ctx, reader: f})
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint, err
}
