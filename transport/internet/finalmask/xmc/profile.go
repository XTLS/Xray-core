package xmc

import "fmt"

type loginProfile struct {
	Username          string
	UUID              UUID
	TexturesValue     string
	TexturesSignature string
}

func profilesFromConfig(configured []*Profile) ([]loginProfile, error) {
	if len(configured) == 0 {
		return nil, fmt.Errorf("empty profiles")
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
			Username:          configuredProfile.Username,
			TexturesValue:     configuredProfile.TexturesValue,
			TexturesSignature: configuredProfile.TexturesSignature,
		}
		copy(profile.UUID[:], configuredProfile.Uuid)
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func findProfile(profiles []loginProfile, username string, uuid UUID) (loginProfile, bool) {
	for _, profile := range profiles {
		if profile.Username == username && profile.UUID == uuid {
			return profile, true
		}
	}
	return loginProfile{}, false
}

func readLoginSuccess(packet *mcPacket) (loginProfile, error) {
	var (
		profile       loginProfile
		username      String
		propertyCount Varint
		propertyName  String
		value         String
		signed        Boolean
		signature     String
	)
	if err := packet.readFields(&profile.UUID, &username, &propertyCount, &propertyName, &value, &signed, &signature); err != nil {
		return loginProfile{}, err
	}
	if propertyCount != 1 || propertyName != "textures" || !signed {
		return loginProfile{}, fmt.Errorf("invalid login profile properties")
	}
	profile.Username = string(username)
	profile.TexturesValue = string(value)
	profile.TexturesSignature = string(signature)
	return profile, nil
}
