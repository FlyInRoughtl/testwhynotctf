package security

import "errors"

type EncryptionProfile struct {
	Depth         int
	MetadataLevel string
}

func DefaultProfile() EncryptionProfile {
	return EncryptionProfile{
		Depth:         3,
		MetadataLevel: "standard",
	}
}

func (p EncryptionProfile) Validate() error {
	if p.Depth < 1 || p.Depth > 10 {
		return errors.New("depth must be 1..10")
	}
	switch p.MetadataLevel {
	case "off", "standard", "max":
	default:
		return errors.New("metadata_level must be off|standard|max")
	}
	return nil
}
