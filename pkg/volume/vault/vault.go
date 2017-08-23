/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilstrings "k8s.io/kubernetes/pkg/util/strings"
	"k8s.io/kubernetes/pkg/volume"
	volumeutil "k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/utils/exec"
)

// This is the primary entrypoint for volume plugins.
func ProbeVolumePlugins() []volume.VolumePlugin {
	return []volume.VolumePlugin{&vaultPlugin{nil}}
}

type vaultPlugin struct {
	host volume.VolumeHost
}

var _ volume.VolumePlugin = &vaultPlugin{}

func wrappedVolumeSpec() volume.Spec {
	return volume.Spec{
		Volume: &v1.Volume{VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}},
	}
}

const (
	vaultPluginName = "kubernetes.io/vault"
)

func (plugin *vaultPlugin) Init(host volume.VolumeHost) error {
	plugin.host = host
	return nil
}

func (plugin *vaultPlugin) GetPluginName() string {
	return vaultPluginName
}

func (plugin *vaultPlugin) GetVolumeName(spec *volume.Spec) (string, error) {
	volumeSource, _ := getVolumeSource(spec)
	if volumeSource == nil {
		return "", fmt.Errorf("Spec does not reference a Vault volume type")
	}

	return spec.Name(), nil
}

func (plugin *vaultPlugin) CanSupport(spec *volume.Spec) bool {
	return spec.Volume != nil && spec.Volume.GitRepo != nil
}

func (plugin *vaultPlugin) RequiresRemount() bool {
	return false
}

func (plugin *vaultPlugin) SupportsMountOption() bool {
	return false
}

func (plugin *vaultPlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *vaultPlugin) NewMounter(spec *volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	return &vaultVolumeMounter{
		vaultVolume: &vaultVolume{
			volName: spec.Name(),
			podUID:  pod.UID,
			plugin:  plugin,
		},
		pod:                 *pod,
		wrappedToken:        spec.Volume.Vault.WrappedToken,
		address:             spec.Volume.Vault.Address,
		storeUnwrappedToken: spec.Volume.Vault.StoreUnwrappedToken,
		srcDstSecrets:       spec.Volume.Vault.SrcDstSecrets,
		exec:                exec.New(),
		opts:                opts,
	}, nil
}

func (plugin *vaultPlugin) NewUnmounter(volName string, podUID types.UID) (volume.Unmounter, error) {
	return &vaultVolumeUnmounter{
		&vaultVolume{
			volName: volName,
			podUID:  podUID,
			plugin:  plugin,
		},
	}, nil
}

func (plugin *vaultPlugin) ConstructVolumeSpec(volumeName, mountPath string) (*volume.Spec, error) {
	vaultVolume := &v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			Vault: &v1.VaultVolumeSource{},
		},
	}
	return volume.NewSpecFromVolume(vaultVolume), nil
}

// gitRepo volumes are directories which are pre-filled from a git repository.
// These do not persist beyond the lifetime of a pod.
type vaultVolume struct {
	volName string
	podUID  types.UID
	plugin  *vaultPlugin
	volume.MetricsNil

	vaultClient *vaultapi.Client
	test        int
}

var _ volume.Volume = &vaultVolume{}

func (v *vaultVolume) GetPath() string {
	name := vaultPluginName
	return v.plugin.host.GetPodVolumeDir(v.podUID, utilstrings.EscapeQualifiedNameForDisk(name), v.volName)
}

// gitRepoVolumeMounter builds git repo volumes.
type vaultVolumeMounter struct {
	*vaultVolume

	pod                 v1.Pod
	wrappedToken        string
	address             string
	storeUnwrappedToken bool
	srcDstSecrets       map[string]string

	exec exec.Interface
	opts volume.VolumeOptions
}

var _ volume.Mounter = &vaultVolumeMounter{}

func (b *vaultVolumeMounter) GetAttributes() volume.Attributes {
	return volume.Attributes{
		ReadOnly:        false,
		Managed:         true,
		SupportsSELinux: true, // xattr change should be okay, TODO: double check
	}
}

// Checks prior to mount operations to verify that the required components (binaries, etc.)
// to mount the volume are available on the underlying node.
// If not, it returns an error
func (b *vaultVolumeMounter) CanMount() error {
	return nil
}

// SetUp creates new directory and clones a git repo.
func (b *vaultVolumeMounter) SetUp(fsGroup *int64) error {
	return b.SetUpAt(b.GetPath(), fsGroup)
}

// SetUpAt creates new directory and clones a git repo.
func (b *vaultVolumeMounter) SetUpAt(dir string, fsGroup *int64) error {
	if volumeutil.IsReady(b.getMetaDir()) {
		return nil
	}

	// Wrap EmptyDir, let it do the setup.
	wrapped, err := b.plugin.host.NewWrapperMounter(b.volName, wrappedVolumeSpec(), &b.pod, b.opts)
	if err != nil {
		return err
	}
	if err := wrapped.SetUpAt(dir, fsGroup); err != nil {
		return err
	}

	// args := []string{"clone", b.source}

	// if len(b.target) != 0 {
	// 	args = append(args, b.target)
	// }
	// if output, err := b.execCommand("git", args, dir); err != nil {
	// 	return fmt.Errorf("failed to exec 'git %s': %s: %v",
	// 		strings.Join(args, " "), output, err)
	// }

	// files, err := ioutil.ReadDir(dir)
	// if err != nil {
	// 	return err
	// }

	// if len(b.revision) == 0 {
	// 	// Done!
	// 	volumeutil.SetReady(b.getMetaDir())
	// 	return nil
	// }

	// var subdir string

	// switch {
	// case b.target == ".":
	// 	// if target dir is '.', use the current dir
	// 	subdir = path.Join(dir)
	// case len(files) == 1:
	// 	// if target is not '.', use the generated folder
	// 	subdir = path.Join(dir, files[0].Name())
	// default:
	// 	// if target is not '.', but generated many files, it's wrong
	// 	return fmt.Errorf("unexpected directory contents: %v", files)
	// }

	// if output, err := b.execCommand("git", []string{"checkout", b.revision}, subdir); err != nil {
	// 	return fmt.Errorf("failed to exec 'git checkout %s': %s: %v", b.revision, output, err)
	// }
	// if output, err := b.execCommand("git", []string{"reset", "--hard"}, subdir); err != nil {
	// 	return fmt.Errorf("failed to exec 'git reset --hard': %s: %v", output, err)
	// }

	// volume.SetVolumeOwnership(b, fsGroup)

	// volumeutil.SetReady(b.getMetaDir())

	// Bootstrap if client is nil
	// if b.vaultClient == nil {
	// 	config := vaultapi.DefaultConfig()
	// 	client, err := vaultapi.NewClient(config)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	client.SetAddress(b.address)
	// 	client.SetToken(b.wrappedToken)

	// 	resp, err := client.Logical().Unwrap("")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if resp == nil {
	// 		return fmt.Error("Vault response was nil during token unwrap")
	// 	}

	// }

	go func() {
		for {
			ioutil.WriteFile(filepath.Join(dir, "time"), []byte(time.Now().String()), 0777)
			time.Sleep(10 * time.Second)
		}
	}()

	ioutil.WriteFile(filepath.Join(dir, "info"), []byte(b.address), 0777)

	volume.SetVolumeOwnership(b, fsGroup)
	volumeutil.SetReady(b.getMetaDir())
	return nil
}

func (b *vaultVolumeMounter) getMetaDir() string {
	return path.Join(b.plugin.host.GetPodPluginDir(b.podUID, utilstrings.EscapeQualifiedNameForDisk(vaultPluginName)), b.volName)
}

func (b *vaultVolumeMounter) execCommand(command string, args []string, dir string) ([]byte, error) {
	cmd := b.exec.Command(command, args...)
	cmd.SetDir(dir)
	return cmd.CombinedOutput()
}

// gitRepoVolumeUnmounter cleans git repo volumes.
type vaultVolumeUnmounter struct {
	*vaultVolume
}

var _ volume.Unmounter = &vaultVolumeUnmounter{}

// TearDown simply deletes everything in the directory.
func (c *vaultVolumeUnmounter) TearDown() error {
	return c.TearDownAt(c.GetPath())
}

// TearDownAt simply deletes everything in the directory.
func (c *vaultVolumeUnmounter) TearDownAt(dir string) error {
	return volume.UnmountViaEmptyDir(dir, c.plugin.host, c.volName, wrappedVolumeSpec(), c.podUID)
}

func getVolumeSource(spec *volume.Spec) (*v1.VaultVolumeSource, bool) {
	var readOnly bool
	var volumeSource *v1.VaultVolumeSource

	if spec.Volume != nil && spec.Volume.Vault != nil {
		volumeSource = spec.Volume.Vault
		readOnly = spec.ReadOnly
	}

	return volumeSource, readOnly
}
