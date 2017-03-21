package vaulter

import (
	"errors"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

type StubMounter struct {
	path string
	mi   *vault.MountInput
}

func (s *StubMounter) Mount(p string, mi *vault.MountInput) error {
	s.path = p
	s.mi = mi
	return nil
}

func TestMountCubbyhole(t *testing.T) {
	sm := &StubMounter{}
	err := Mount(sm, "cubbyhole/", &MountConfiguration{
		Type:        "cubbyhole",
		Description: "A cubbyhole mount for iRODS configs",
	})
	if err != nil {
		t.Error(err)
	}
	if sm.mi.Type != "cubbyhole" {
		t.Errorf("type was %s instead of %s", sm.mi.Type, "cubbyhole")
	}
	if sm.mi.Description != "A cubbyhole mount for iRODS configs" {
		t.Errorf("description was %s instead of '%s'", sm.mi.Description, "A cubbyhole mount for iRODS configs")
	}
}

func TestMountPKI(t *testing.T) {
	sm := &StubMounter{}
	err := Mount(sm, "pki/", &MountConfiguration{
		Type:        "pki",
		Description: "A pki backend for HTCondor jobs",
	})
	if err != nil {
		t.Error(err)
	}
	if sm.mi.Type != "pki" {
		t.Errorf("type was %s instead of %s", sm.mi.Type, "pki")
	}
	if sm.mi.Description != "A pki backend for HTCondor jobs" {
		t.Errorf("description was %s instead of '%s'", sm.mi.Description, "A pki backend for HTCondor jobs")
	}
}

type StubMountLister struct {
	returnMiss bool
	returnErr  bool
}

func (s *StubMountLister) ListMounts() (map[string]*vault.MountOutput, error) {
	if s.returnErr {
		return nil, errors.New("test error")
	}
	if s.returnMiss {
		return map[string]*vault.MountOutput{
			"cubbyhole2/": &vault.MountOutput{},
			"pki2/":       &vault.MountOutput{},
		}, nil
	}
	return map[string]*vault.MountOutput{
		"cubbyhole/": &vault.MountOutput{},
		"pki/":       &vault.MountOutput{},
	}, nil
}

func TestIsCubbyholeMounted(t *testing.T) {
	lister := &StubMountLister{}
	m, err := IsMounted(lister, "cubbyhole")
	if err != nil {
		t.Error(err)
	}
	if !m {
		t.Error("the cubbyhole mount was not found")
	}

	lister = &StubMountLister{
		returnMiss: true,
	}
	m, err = IsMounted(lister, "cubbyhole")
	if err != nil {
		t.Error(err)
	}
	if m {
		t.Error("the cubbyhole mount was found")
	}

	lister = &StubMountLister{
		returnErr: true,
	}
	m, err = IsMounted(lister, "cubbyhole")
	if err == nil {
		t.Error(err)
	}
	if m {
		t.Error("the cubbyhole mount was found")
	}
}

func TestIsPKIMounted(t *testing.T) {
	lister := &StubMountLister{}
	m, err := IsMounted(lister, "pki")
	if err != nil {
		t.Error(err)
	}
	if !m {
		t.Error("the pki backend was not found")
	}

	lister = &StubMountLister{
		returnMiss: true,
	}
	m, err = IsMounted(lister, "pki")
	if err != nil {
		t.Error(err)
	}
	if m {
		t.Error("the pki backend mount was found")
	}

	lister = &StubMountLister{
		returnErr: true,
	}
	m, err = IsMounted(lister, "pki")
	if err == nil {
		t.Error(err)
	}
	if m {
		t.Error("the pki backend mount was found")
	}
}

type StubMountConfigGetter struct {
	path string
}

func (s *StubMountConfigGetter) MountConfig(path string) (*vault.MountConfigOutput, error) {
	s.path = path
	return &vault.MountConfigOutput{}, nil
}

func TestPKIMountConfig(t *testing.T) {
	sg := &StubMountConfigGetter{}
	mo, err := MountConfig(sg, "pki/")
	if err != nil {
		t.Error(err)
	}
	if mo == nil {
		t.Error("MountConfigOutput was nil")
	}
	if sg.path != "pki/" {
		t.Errorf("path was '%s' instead of 'pki/'", sg.path)
	}
}
