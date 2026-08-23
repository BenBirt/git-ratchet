// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitutil

import (
	"fmt"
	"strings"
)

// Fsck runs "git fsck --no-progress" on the repository and returns a non-nil
// error if the object database is inconsistent (hash mismatches, missing
// objects, malformed DAG structure, etc.).
func Fsck(repoDir string) error {
	if _, err := Git(repoDir).Run("fsck", "--no-progress"); err != nil {
		return err
	}
	return nil
}

// ListReplaceRefs returns all refs under refs/replace/. An empty slice means
// no replace refs exist.
func ListReplaceRefs(repoDir string) ([]string, error) {
	out, err := Git(repoDir).Run("for-each-ref", "--format=%(refname)", "refs/replace/")
	if err != nil {
		return nil, fmt.Errorf("listing replace refs: %w", err)
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}
