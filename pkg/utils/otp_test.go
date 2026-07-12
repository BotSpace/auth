package utils

import "testing"

func TestRandomOtpShape(t *testing.T) {
	first := RandomOtp(64)
	second := RandomOtp(64)
	if len(first) != 64 || len(second) != 64 {
		t.Fatalf("unexpected lengths: %d, %d", len(first), len(second))
	}
	if first == second {
		t.Fatal("two independently generated OTP sequences must differ")
	}
	for _, value := range []string{first, second} {
		for _, char := range value {
			if char < '0' || char > '9' {
				t.Fatalf("OTP contains non-digit %q", char)
			}
		}
	}
}

func TestRandomStringRejectsEmptyAlphabet(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected empty alphabet to panic")
		}
	}()
	_ = RandomString(1, "")
}
