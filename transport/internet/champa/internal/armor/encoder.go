package armor

import (
	"encoding/base64"
	"io"
)

// https://amp.dev/boilerplate/
// https://amp.dev/documentation/guides-and-tutorials/learn/spec/amp-boilerplate/?format=websites
// https://amp.dev/documentation/guides-and-tutorials/learn/spec/amphtml/?format=websites#the-amp-html-format
const (
	boilerplateStart = `<!doctype html>
<html amp>
<head>
<meta charset="utf-8">
<script async src="https://cdn.ampproject.org/v0.js"></script>
<link rel="canonical" href="#">
<meta name="viewport" content="width=device-width">
<style amp-boilerplate>body{-webkit-animation:-amp-start 8s steps(1,end) 0s 1 normal both;-moz-animation:-amp-start 8s steps(1,end) 0s 1 normal both;-ms-animation:-amp-start 8s steps(1,end) 0s 1 normal both;animation:-amp-start 8s steps(1,end) 0s 1 normal both}@-webkit-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-moz-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-ms-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-o-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}</style><noscript><style amp-boilerplate>body{-webkit-animation:none;-moz-animation:none;-ms-animation:none;animation:none}</style></noscript>
</head>
<body>
`
	boilerplateEnd = `</body>
</html>`
)

const (
	// We restrict the amount of text may go inside an HTML element, in
	// order to limit the amount a decoder may have to buffer.
	elementSizeLimit = 32 * 1024

	// The payload is conceptually a long base64-encoded string, but we
	// break the string into short chunks separated by whitespace. This is
	// to protect against modification by AMP caches, which reportedly may
	// truncate long words in text:
	// https://bugs.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/25985#note_2592348
	bytesPerChunk = 32

	// We set the number of chunks per element so as to stay under
	// elementSizeLimit. Here, we assume that there is 1 byte of whitespace
	// after each chunk (with an additional whitespace byte at the beginning
	// of the element).
	chunksPerElement = (elementSizeLimit - 1) / (bytesPerChunk + 1)
)

// The AMP armor encoder is a chain of a base64 encoder (base64.NewEncoder) and
// an HTML element encoder (elementEncoder). A top-level encoder (armorEncoder)
// coordinates these two, and handles prepending and appending the AMP
// boilerplate. armorEncoder's Write method writes data into the base64 encoder,
// where it makes its way through the chain.

// NewEncoder returns a new AMP armor encoder. Anything written to the returned
// io.WriteCloser will be encoded and written to w. The caller must call Close
// to flush any partially written data and output the AMP boilerplate trailer.
func NewEncoder(w io.Writer) (io.WriteCloser, error) {
	// Immediately write the AMP boilerplate header.
	_, err := w.Write([]byte(boilerplateStart))
	if err != nil {
		return nil, err
	}

	element := &elementEncoder{w: w}
	// Write a server–client protocol version indicator, outside the base64
	// layer.
	_, err = element.Write([]byte{'0'})
	if err != nil {
		return nil, err
	}

	base64 := base64.NewEncoder(base64.StdEncoding, element)
	return &armorEncoder{
		w:       w,
		element: element,
		base64:  base64,
	}, nil
}

type armorEncoder struct {
	base64  io.WriteCloser
	element *elementEncoder
	w       io.Writer
}

func (enc *armorEncoder) Write(p []byte) (int, error) {
	// Write into the chain base64 | element | w.
	return enc.base64.Write(p)
}

func (enc *armorEncoder) Close() error {
	// Close the base64 encoder first, to flush out any buffered data and
	// the final padding.
	err := enc.base64.Close()
	if err != nil {
		return err
	}

	// Next, close the element encoder, to close any open elements.
	err = enc.element.Close()
	if err != nil {
		return err
	}

	// Finally, output the AMP boilerplate trailer.
	_, err = enc.w.Write([]byte(boilerplateEnd))
	if err != nil {
		return err
	}

	return nil
}

// elementEncoder arranges written data into pre elements, with the text within
// separated into chunks. It does no HTML encoding, so data written must not
// contain any bytes that are meaningful in HTML.
type elementEncoder struct {
	w              io.Writer
	chunkCounter   int
	elementCounter int
}

func (enc *elementEncoder) Write(p []byte) (n int, err error) {
	total := 0
	for len(p) > 0 {
		if enc.elementCounter == 0 && enc.chunkCounter == 0 {
			_, err := enc.w.Write([]byte("<pre>\n"))
			if err != nil {
				return total, err
			}
		}

		n := bytesPerChunk - enc.chunkCounter
		if n > len(p) {
			n = len(p)
		}
		nn, err := enc.w.Write(p[:n])
		if err != nil {
			return total, err
		}
		total += nn
		p = p[n:]

		enc.chunkCounter += n
		if enc.chunkCounter >= bytesPerChunk {
			enc.chunkCounter = 0
			enc.elementCounter += 1
			nn, err = enc.w.Write([]byte("\n"))
			if err != nil {
				return total, err
			}
			total += nn
		}

		if enc.elementCounter >= chunksPerElement {
			enc.elementCounter = 0
			nn, err = enc.w.Write([]byte("</pre>\n"))
			if err != nil {
				return total, err
			}
			total += nn
		}
	}
	return total, nil
}

func (enc *elementEncoder) Close() error {
	var err error
	if !(enc.elementCounter == 0 && enc.chunkCounter == 0) {
		if enc.chunkCounter == 0 {
			_, err = enc.w.Write([]byte("</pre>\n"))
		} else {
			_, err = enc.w.Write([]byte("\n</pre>\n"))
		}
	}
	return err
}
