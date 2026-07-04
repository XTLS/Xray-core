package videochannel

import (
	"errors"
	"fmt"
	"strings"

	grqr "github.com/zarazaex69/gr/qr"
	grtile "github.com/zarazaex69/gr/tile"
)

// ErrUnexpectedQRFrameSize is returned when the decoded frame size does not match the expected dimensions.
var ErrUnexpectedQRFrameSize = errors.New("unexpected qr frame size")

func eccLevel(level string) grqr.ECCLevel {
	switch level {
	case "medium":
		return grqr.ECCMedium
	case "high":
		return grqr.ECCQuartile
	case "highest":
		return grqr.ECCHigh
	default:
		return grqr.ECCLow
	}
}

func renderVisualFrame(
	payload []byte,
	width, height int,
	codec, recoveryLevel string,
	tileModule, tileRS int,
) ([]byte, error) {
	if codec == "tile" {
		return renderTileFrame(payload, tileModule, tileRS)
	}
	return renderQRFrame(payload, width, height, recoveryLevel)
}

func renderQRFrame(payload []byte, width, height int, recoveryLevel string) ([]byte, error) {
	if len(payload) == 0 {
		frame := make([]byte, width*height)
		for i := range frame {
			frame[i] = 0xff
		}
		return frame, nil
	}

	c, err := grqr.New(grqr.Config{
		FrameW: width,
		FrameH: height,
		Margin: 2,
		ECC:    eccLevel(recoveryLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("qr codec: %w", err)
	}

	result, err := c.Encode(payload)
	if err != nil {
		return nil, fmt.Errorf("qr encode: %w", err)
	}
	return result, nil
}

func renderTileFrame(payload []byte, tileModule, tileRS int) ([]byte, error) {
	if len(payload) == 0 {
		frame := make([]byte, grtile.FrameW*grtile.FrameH)
		for i := range frame {
			frame[i] = 0xff
		}
		return frame, nil
	}

	c, err := grtile.New(grtile.Config{Module: tileModule, RSPercent: tileRS})
	if err != nil {
		return nil, fmt.Errorf("tile codec: %w", err)
	}

	result, err := c.Encode(payload, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("tile encode: %w", err)
	}
	return result, nil
}

func extractVisualPayload(frame []byte, width, height int, codec string, tileModule, tileRS int) ([]byte, error) {
	if codec == "tile" {
		return extractTilePayload(frame, tileModule, tileRS)
	}
	return extractQRPayload(frame, width, height)
}

func extractQRPayload(frame []byte, width, height int) ([]byte, error) {
	if len(frame) != width*height {
		return nil, fmt.Errorf("%w: got %d expected %dx%d=%d",
			ErrUnexpectedQRFrameSize, len(frame), width, height, width*height)
	}

	c, err := grqr.New(grqr.Config{
		FrameW: width,
		FrameH: height,
		Margin: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("qr codec: %w", err)
	}

	data, err := c.Decode(frame)
	if err != nil {
		if strings.Contains(err.Error(), "NotFoundException") || strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("decode: %w", err)
	}

	return data, nil
}

func extractTilePayload(frame []byte, tileModule, tileRS int) ([]byte, error) {
	if len(frame) != grtile.FrameW*grtile.FrameH {
		return nil, nil
	}

	c, err := grtile.New(grtile.Config{Module: tileModule, RSPercent: tileRS})
	if err != nil {
		return nil, fmt.Errorf("tile codec: %w", err)
	}

	result, err := c.Decode(frame)
	if err != nil {
		return nil, nil //nolint:nilerr // decode failures are treated as "no payload" by callers
	}

	return result.Payload, nil
}
