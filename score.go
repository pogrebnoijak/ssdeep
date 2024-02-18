package ssdeep

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
)

var (
	// ErrEmptyHash is returned when no hash string is provided for scoring.
	ErrEmptyHash = errors.New("empty string")

	// ErrInvalidFormat is returned when a hash string is malformed.
	ErrInvalidFormat = errors.New("invalid ssdeep format")
)

// Distance computes the match score between two fuzzy hash signatures.
// Returns a value from zero to 100 indicating the match score of the two signatures.
// A match score of zero indicates the signatures did not match.
// Returns an error when one of the inputs are not valid signatures.
func Distance(hash1, hash2 string) (int, error) {
	var score int
	hash1BlockSize, hash1String1, hash1String2, err := splitSsdeep(hash1)
	if err != nil {
		return score, err
	}
	hash2BlockSize, hash2String1, hash2String2, err := splitSsdeep(hash2)
	if err != nil {
		return score, err
	}

	if hash1BlockSize == hash2BlockSize &&
		len(hash1String1) == len(hash2String1) && len(hash1String2) == len(hash2String2) &&
		hash1String1 == hash2String1 && hash1String2 == hash2String2 {
		return 100, nil
	}

	// We can only compare equal or *2 block sizes
	if hash1BlockSize != hash2BlockSize && hash1BlockSize != hash2BlockSize*2 && hash2BlockSize != hash1BlockSize*2 {
		return score, err
	}

	if hash1BlockSize == hash2BlockSize {
		d1 := scoreDistance(hash1String1, hash2String1, hash1BlockSize)
		d2 := scoreDistance(hash1String2, hash2String2, hash1BlockSize*2)
		score = int(math.Max(float64(d1), float64(d2)))
	} else if hash1BlockSize == hash2BlockSize*2 {
		score = scoreDistance(hash1String1, hash2String2, hash1BlockSize)
	} else {
		score = scoreDistance(hash1String2, hash2String1, hash2BlockSize)
	}
	return score, nil
}

func splitSsdeep(hash string) (int, string, string, error) {
	if hash == "" {
		return 0, "", "", ErrEmptyHash
	}

	hashBytes := []byte(hash)

	var index int
	var buffer bytes.Buffer
	buffer.Grow(len(hashBytes))

	for i, b := range hashBytes {
		if b == ':' {
			index = i + 1
			break
		}
		buffer.WriteByte(b)
	}
	if index == 0 {
		return 0, "", "", ErrInvalidFormat
	}

	blockSize, err := strconv.Atoi(buffer.String())
	if err != nil {
		return blockSize, "", "", fmt.Errorf("%s: %w", ErrInvalidFormat.Error(), err)
	}
	buffer.Reset()

	indexUpdated := false
	seq := 0
	var prev byte = ':'
	for i, curr := range hashBytes[index:] {
		if curr == ':' {
			indexUpdated = true
			index = index + i + 1
			break
		}
		if curr == prev {
			seq++
			if seq < 3 {
				buffer.WriteByte(curr)
			}
		} else {
			buffer.WriteByte(curr)
			seq = 0
			prev = curr
		}
	}
	if !indexUpdated {
		return 0, "", "", ErrInvalidFormat
	}

	part1 := buffer.String()
	buffer.Reset()

	seq = 0
	prev = ':'
	for _, curr := range hashBytes[index:] {
		if curr == ':' {
			return 0, "", "", ErrInvalidFormat
		}
		if curr == prev {
			seq++
			if seq < 3 {
				buffer.WriteByte(curr)
			}
		} else {
			buffer.WriteByte(curr)
			seq = 0
			prev = curr
		}
	}

	part2 := buffer.String()

	return blockSize, part1, part2, nil
}

func hasCommonSubstring(h1, h2 string) bool {
	l1 := len(h1)
	l2 := len(h2)
	if l1 < rollingWindow || l2 < rollingWindow {
		return false
	}

	hashes := make([]uint32, 0, spamSumLength-rollingWindow+1)
	state := rollingState{}
	for i := 0; i < rollingWindow-1; i++ {
		state.rollHash(h1[i])
	}
	for i := rollingWindow - 1; i < l1; i++ {
		state.rollHash(h1[i])
		hashes = append(hashes, state.rollSum())
	}

	state = rollingState{}
	for j := 0; j < rollingWindow-1; j++ {
		state.rollHash(h2[j])
	}
	for j := 0; j < l2-rollingWindow+1; j++ {
		state.rollHash(h2[j+rollingWindow-1])
		h := state.rollSum()
		for i, hash := range hashes {
			if hash == h && h1[i:i+rollingWindow] == h2[j:j+rollingWindow] {
				return true
			}
		}
	}

	return false
}

func scoreDistance(h1, h2 string, blockSize int) int {
	if !hasCommonSubstring(h1, h2) {
		return 0
	}

	d := distance(h1, h2)
	d = (d * spamSumLength) / (len(h1) + len(h2))
	d = (100 * d) / spamSumLength
	d = 100 - d

	if blockSize >= blockSizeSmallLimit {
		return d
	}

	matchSize := int(float64(blockSize) / blockMin * math.Min(float64(len(h1)), float64(len(h2))))
	if d > matchSize {
		return matchSize
	}
	return d
}
