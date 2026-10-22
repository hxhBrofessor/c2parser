package csconfig

import (
	"bytes"
	"fmt"
	"testing"
)

func s1f2FalseAnchor(key byte) []byte {
	junk := bytes.Repeat([]byte{0x91}, 0x2000)
	for i, b := range syntheticOID {
		junk[0x1000+i] = b ^ key
	}
	return junk
}

func TestS1F2ValidConfigAfterFalseAnchors(t *testing.T) {
	for _, count := range []int{1, 4, 16} {
		t.Run(fmt.Sprintf("anchors_%d", count), func(t *testing.T) {
			data := make([]byte, 0, count*0x2000+0x1c00)
			for i := 0; i < count; i++ {
				key := byte(0)
				if i%2 != 0 {
					key = 0x43
				}
				data = append(data, s1f2FalseAnchor(key)...)
			}
			data = append(data, makePlainFixture(0x1800, 0x2e, fixtureSettings(76))...)
			c := New(Options{Limiter: NewLimiter(2)})
			defer c.Close()
			reviewFeed(c, data, []int{4096})
			got, ok := c.Result()
			if !ok || got == nil || got.XORKey != 0x2e {
				t.Fatalf("false anchors=%d: config=%+v reason=%q", count, got, c.Reason())
			}
		})
	}
}

func TestS1F2AnchorEvaluationAllowance(t *testing.T) {
	const documentedAllowance = 32
	data := make([]byte, 0, (documentedAllowance+1)*0x2000+0x1c00)
	for i := 0; i < documentedAllowance+1; i++ {
		data = append(data, s1f2FalseAnchor(0)...)
	}
	data = append(data, makePlainFixture(0x1800, 0x2e, fixtureSettings(76))...)
	c := New(Options{Limiter: NewLimiter(2)})
	defer c.Close()
	reviewFeed(c, data, []int{4096})
	_, ok := c.Result()
	if ok || c.Reason() != ReasonWorkBudgetExhausted {
		t.Fatalf("ok=%v reason=%q", ok, c.Reason())
	}
	if c.workUsed > documentedAllowance*maxPatchSize {
		t.Fatalf("work=%d exceeds documented bound %d", c.workUsed, documentedAllowance*maxPatchSize)
	}
}

func TestS1F2SuccessfulCarvesHaveNoReason(t *testing.T) {
	plain := makePlainFixture(0x1800, 0x2e, fixtureSettings(76))
	tests := []struct {
		name string
		data []byte
	}{
		{name: "plain", data: plain},
	}
	for _, offset := range []int{0, 7, 1023} {
		decoded := make([]byte, 64<<10)
		copy(decoded, plain)
		wrapped := makeXorEncodedFixture(decoded, [4]byte{9, 8, 7, 6}, 0)
		data := append(bytes.Repeat([]byte{0x40}, offset), wrapped...)
		tests = append(tests, struct {
			name string
			data []byte
		}{name: fmtReview(64<<10, offset), data: data})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(Options{Limiter: NewLimiter(2)})
			defer c.Close()
			reviewFeed(c, tt.data, []int{4096})
			got, ok := c.Result()
			if !ok || got == nil || c.Reason() != ReasonNone {
				t.Fatalf("config=%+v ok=%v reason=%q", got, ok, c.Reason())
			}
		})
	}
}

func TestS1F2ConfigAfterCertificateLikeOIDBlob(t *testing.T) {
	certLike := bytes.Repeat([]byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x01}, 1024)
	copy(certLike[0x1000:], syntheticOID)
	data := append(certLike, makePlainFixture(0x1800, 0x2e, fixtureSettings(76))...)
	c := New(Options{Limiter: NewLimiter(2)})
	defer c.Close()
	reviewFeed(c, data, []int{4096})
	got, ok := c.Result()
	if !ok || got == nil || got.XORKey != 0x2e {
		t.Fatalf("config=%+v ok=%v reason=%q", got, ok, c.Reason())
	}
}
