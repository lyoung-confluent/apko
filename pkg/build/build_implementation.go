// Copyright 2022 Chainguard, Inc.
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

package build

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/exec"
	apkofs "chainguard.dev/apko/pkg/fs"
	"chainguard.dev/apko/pkg/s6"
	"chainguard.dev/apko/pkg/sbom"
	"chainguard.dev/apko/pkg/tarball"
	"github.com/google/go-containerregistry/pkg/name"
	v1tar "github.com/google/go-containerregistry/pkg/v1/tarball"
)

type BuildImplementation interface {
	Refresh(*Options) (*s6.Context, *exec.Executor, error)
	BuildTarball(o *Options) (string, error)
	GenerateSBOM(o *Options) error
}

type defaultBuildImplementation struct{}

func (di *defaultBuildImplementation) Refresh(o *Options) (*s6.Context, *exec.Executor, error) {
	if strings.HasPrefix(o.TarballPath, "/tmp/apko") {
		o.TarballPath = ""
	}

	hostArch := types.ParseArchitecture(runtime.GOARCH)

	execOpts := []exec.Option{exec.WithProot(o.UseProot)}
	if o.UseProot && !o.Arch.Compatible(hostArch) {
		o.Log.Printf("%q requires QEMU (not compatible with %q)", o.Arch, hostArch)
		execOpts = append(execOpts, exec.WithQemu(o.Arch.ToQEmu()))
	}

	executor, err := exec.New(o.WorkDir, o.Log, execOpts...)
	if err != nil {
		return nil, nil, err
	}

	return s6.New(o.WorkDir, o.Log), executor, nil
}

func (di *defaultBuildImplementation) BuildTarball(o *Options) (string, error) {
	var outfile *os.File
	var err error

	if o.TarballPath != "" {
		outfile, err = os.Create(o.TarballPath)
	} else {
		outfile, err = os.CreateTemp("", "apko-*.tar.gz")
	}
	if err != nil {
		return "", fmt.Errorf("opening the build context tarball path failed: %w", err)
	}
	o.TarballPath = outfile.Name()
	defer outfile.Close()

	tw, err := tarball.NewContext(tarball.WithSourceDateEpoch(o.SourceDateEpoch))
	if err != nil {
		return "", fmt.Errorf("failed to construct tarball build context: %w", err)
	}

	if err := tw.WriteArchive(outfile, apkofs.DirFS(o.WorkDir)); err != nil {
		return "", fmt.Errorf("failed to generate tarball for image: %w", err)
	}

	o.Log.Printf("built image layer tarball as %s", outfile.Name())
	return outfile.Name(), nil
}

// GenerateSBOM runs the sbom generation
func (di *defaultBuildImplementation) GenerateSBOM(o *Options) error {
	if len(o.SBOMFormats) == 0 {
		o.Log.Printf("skipping SBOM generation")
		return nil
	}
	o.Log.Printf("generating SBOM")

	// TODO(puerco): Split GenerateSBOM into context implementation
	s := sbom.NewWithWorkDir(o.WorkDir, o.Arch)

	v1Layer, err := v1tar.LayerFromFile(o.TarballPath)
	if err != nil {
		return fmt.Errorf("failed to create OCI layer from tar.gz: %w", err)
	}

	digest, err := v1Layer.Digest()
	if err != nil {
		return fmt.Errorf("could not calculate layer digest: %w", err)
	}

	// Parse the image reference
	if len(o.Tags) > 0 {
		tag, err := name.NewTag(o.Tags[0])
		if err != nil {
			return fmt.Errorf("parsing tag %s: %w", o.Tags[0], err)
		}
		s.Options.ImageInfo.Tag = tag.TagStr()
		s.Options.ImageInfo.Name = tag.String()
	}

	// Generate the packages externally as we may
	// move the package reader somewhere else
	packages, err := s.ReadPackageIndex()
	if err != nil {
		return fmt.Errorf("getting installed packages from sbom: %w", err)
	}
	s.Options.ImageInfo.Arch = o.Arch
	s.Options.ImageInfo.Digest = digest.String()
	s.Options.OutputDir = o.SBOMPath
	s.Options.Packages = packages
	s.Options.Formats = o.SBOMFormats

	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}
