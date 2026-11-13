package xmc

import (
	"fmt"
	"io"
)

const maxLoginProperties = 16

type loginProperty struct {
	Name      string
	Value     string
	Signature string
	Signed    bool
}

// loginProperties is the list of profile properties carried by the Login
// Success packet. It implements the field interface so it can be read and
// written together with the other packet fields.
type loginProperties []loginProperty

func (p *loginProperties) readFrom(r io.Reader) error {
	var count Varint
	if err := count.readFrom(r); err != nil {
		return fmt.Errorf("read property count: %w", err)
	}
	if count < 0 || count > maxLoginProperties {
		return fmt.Errorf("read property count: bad value: %d", count)
	}

	properties := make([]loginProperty, 0, int(count))
	for range int(count) {
		var (
			name  String
			value String
			flag  Boolean
		)
		if err := name.readFrom(r); err != nil {
			return fmt.Errorf("read property name: %w", err)
		}
		if err := value.readFrom(r); err != nil {
			return fmt.Errorf("read property value: %w", err)
		}
		if err := flag.readFrom(r); err != nil {
			return fmt.Errorf("read property signature flag: %w", err)
		}

		property := loginProperty{
			Name:   string(name),
			Value:  string(value),
			Signed: bool(flag),
		}
		if property.Signed {
			var signature String
			if err := signature.readFrom(r); err != nil {
				return fmt.Errorf("read property signature: %w", err)
			}
			property.Signature = string(signature)
		}
		properties = append(properties, property)
	}

	*p = properties
	return nil
}

func (p *loginProperties) writeTo(w io.Writer) error {
	count := Varint(len(*p))
	if err := count.writeTo(w); err != nil {
		return fmt.Errorf("write property count: %w", err)
	}

	for _, property := range *p {
		name := String(property.Name)
		value := String(property.Value)
		signed := Boolean(property.Signed)
		if err := name.writeTo(w); err != nil {
			return fmt.Errorf("write property name: %w", err)
		}
		if err := value.writeTo(w); err != nil {
			return fmt.Errorf("write property value: %w", err)
		}
		if err := signed.writeTo(w); err != nil {
			return fmt.Errorf("write property signature flag: %w", err)
		}
		if property.Signed {
			signature := String(property.Signature)
			if err := signature.writeTo(w); err != nil {
				return fmt.Errorf("write property signature: %w", err)
			}
		}
	}

	return nil
}

type loginProfile struct {
	Username   string
	UUID       UUID
	Properties loginProperties
}

func (p loginProfile) textures() (loginProperty, bool) {
	for _, property := range p.Properties {
		if property.Name == "textures" {
			return property, true
		}
	}
	return loginProperty{}, false
}

func sameProfileIdentity(a, b loginProfile) bool {
	return a.Username == b.Username && a.UUID == b.UUID
}

// sameLoginProfile also compares the signed textures, so a client that has a
// local copy of the signed profile can detect a server returning another one.
func sameLoginProfile(a, b loginProfile) bool {
	if !sameProfileIdentity(a, b) {
		return false
	}

	aTextures, aFound := a.textures()
	bTextures, bFound := b.textures()
	if !aFound || !bFound {
		return aFound == bFound
	}
	return aTextures.Value == bTextures.Value && aTextures.Signature == bTextures.Signature
}

func profilesFromConfig(configured []*Profile) ([]loginProfile, error) {
	if len(configured) == 0 {
		return nil, nil
	}

	profiles := make([]loginProfile, 0, len(configured))
	for _, configuredProfile := range configured {
		if configuredProfile == nil || configuredProfile.Username == "" {
			return nil, fmt.Errorf("invalid profile")
		}
		if len(configuredProfile.Uuid) != len(UUID{}) {
			return nil, fmt.Errorf("bad profile UUID length: %d", len(configuredProfile.Uuid))
		}
		if configuredProfile.TexturesValue == "" || configuredProfile.TexturesSignature == "" {
			return nil, fmt.Errorf("incomplete profile textures")
		}

		profile := loginProfile{
			Username: configuredProfile.Username,
			Properties: loginProperties{
				{
					Name:      "textures",
					Value:     configuredProfile.TexturesValue,
					Signature: configuredProfile.TexturesSignature,
					Signed:    true,
				},
			},
		}
		copy(profile.UUID[:], configuredProfile.Uuid)
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func findProfile(profiles []loginProfile, username string, uuid UUID) (loginProfile, bool) {
	for _, profile := range profiles {
		if sameProfileIdentity(profile, loginProfile{Username: username, UUID: uuid}) {
			return profile, true
		}
	}
	return loginProfile{}, false
}

func propertyListFromYggdrasil(properties []yggdrasilProperty) loginProperties {
	result := make(loginProperties, 0, len(properties))
	for _, property := range properties {
		result = append(result, loginProperty{
			Name:      property.Name,
			Value:     property.Value,
			Signature: property.Signature,
			Signed:    property.Signature != "",
		})
	}
	return result
}

func readLoginSuccess(packet *mcPacket) (loginProfile, error) {
	var (
		profile  loginProfile
		username String
	)
	if err := packet.readFields(&profile.UUID, &username, &profile.Properties); err != nil {
		return loginProfile{}, err
	}
	profile.Username = string(username)
	return profile, nil
}

func writeLoginSuccess(w io.Writer, profile loginProfile) error {
	username := String(profile.Username)
	return writePacket(w, 0x02, &profile.UUID, &username, &profile.Properties)
}
