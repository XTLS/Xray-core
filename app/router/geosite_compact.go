package router

import (
	"encoding/gob"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/strmatcher"
)

type geoSiteListGob struct {
	Sites map[string][]byte
}

func SerializeGeoSiteList(sites []*GeoSite, w io.Writer) error {
	data := geoSiteListGob{
		Sites: make(map[string][]byte),
	}

	for _, site := range sites {
		if site == nil {
			continue
		}
		var buf bytesWriter
		if err := SerializeDomainMatcher(site.Domain, &buf); err != nil {
			return err
		}
		data.Sites[site.CountryCode] = buf.Bytes()
	}

	return gob.NewEncoder(w).Encode(data)
}

type bytesWriter struct {
	data []byte
}

func (w *bytesWriter) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *bytesWriter) Bytes() []byte {
	return w.data
}

func LoadGeoSiteMatcher(r io.Reader, countryCode string) (*strmatcher.MphMatcherGroup, error) {
	var data geoSiteListGob
	if err := gob.NewDecoder(r).Decode(&data); err != nil {
		return nil, err
	}

	siteData, ok := data.Sites[countryCode]
	if !ok {
		return nil, errors.New("country code not found")
	}

	return NewDomainMatcherFromBuffer(siteData)
}
