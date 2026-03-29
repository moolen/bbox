package bridge

import "io"

func ReadBoundedBody(body io.ReadCloser, maxBytes int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()

	if maxBytes <= 0 {
		data, err := io.ReadAll(body)
		return data, false, err
	}

	limited, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(limited)) > maxBytes {
		return limited[:maxBytes], true, nil
	}
	return limited, false, nil
}
