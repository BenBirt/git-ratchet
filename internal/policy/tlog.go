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

package policy

import (
	"fmt"
	"os"

	fpolicy "github.com/transparency-dev/formats/policy"
)

// tlog mode uses the C2SP tlog-policy format, https://c2sp.org/tlog-policy,
// parsed and evaluated by github.com/transparency-dev/formats/policy. This is
// the conformant policy format; the bespoke one policy.go parses predates it
// and is expected to be replaced by this one.

// FromPath reads and parses a tlog-policy file.
func FromPath(path string) (*fpolicy.TLogPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p fpolicy.TLogPolicy
	if err := p.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("parsing policy %s: %w", path, err)
	}
	return &p, nil
}
