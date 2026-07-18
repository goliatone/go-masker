package masker

import (
	"fmt"
	"sync"
	"testing"
)

type concurrentPayload struct {
	Password string
	Nested   map[string]any
	Values   []string `mask:"redact"`
}

func TestMaskConcurrent(t *testing.T) {
	for _, cacheEnabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("cache_%t", cacheEnabled), func(t *testing.T) {
			m, err := New(WithProfile(ProfileSecure), WithCache(cacheEnabled))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			m.Freeze()

			input := concurrentPayload{
				Password: "super-secret",
				Nested: map[string]any{
					"clientSecret": "nested-secret",
					"visible":      "value",
				},
				Values: []string{"first-secret", "second-secret"},
			}

			const workers = 32
			const iterations = 25
			start := make(chan struct{})
			errs := make(chan error, workers)
			var wg sync.WaitGroup
			for worker := 0; worker < workers; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for i := 0; i < iterations; i++ {
						maskedAny, maskErr := m.Mask(input)
						if maskErr != nil {
							errs <- maskErr
							return
						}
						masked := maskedAny.(concurrentPayload)
						if masked.Password != RedactedValue {
							errs <- fmt.Errorf("password = %q", masked.Password)
							return
						}
						if masked.Nested["clientSecret"] != RedactedValue {
							errs <- fmt.Errorf("clientSecret = %q", masked.Nested["clientSecret"])
							return
						}
						if masked.Values[0] != RedactedValue || masked.Values[1] != RedactedValue {
							errs <- fmt.Errorf("values were not redacted: %v", masked.Values)
							return
						}
					}
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

func TestMaskReturnsIndependentCopies(t *testing.T) {
	m, err := New(WithProfile(ProfileSecure))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.Freeze()

	input := concurrentPayload{
		Password: "super-secret",
		Nested:   map[string]any{"client_secret": "nested-secret"},
		Values:   []string{"first-secret"},
	}
	firstAny, err := m.Mask(input)
	if err != nil {
		t.Fatalf("first Mask: %v", err)
	}
	secondAny, err := m.Mask(input)
	if err != nil {
		t.Fatalf("second Mask: %v", err)
	}
	first := firstAny.(concurrentPayload)
	second := secondAny.(concurrentPayload)

	first.Nested["client_secret"] = "changed"
	first.Values[0] = "changed"
	if second.Nested["client_secret"] != RedactedValue {
		t.Fatalf("second nested value changed: %v", second.Nested)
	}
	if second.Values[0] != RedactedValue {
		t.Fatalf("second slice changed: %v", second.Values)
	}
	if input.Nested["client_secret"] != "nested-secret" || input.Values[0] != "first-secret" {
		t.Fatal("Mask mutated its input")
	}
}

func TestMaskNil(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	masked, err := m.Mask(nil)
	if err != nil {
		t.Fatalf("Mask(nil): %v", err)
	}
	if masked != nil {
		t.Fatalf("Mask(nil) = %#v, want nil", masked)
	}
}

func TestGenericMaskNil(t *testing.T) {
	masked, err := Mask[any](nil)
	if err != nil {
		t.Fatalf("Mask[any](nil): %v", err)
	}
	if masked != nil {
		t.Fatalf("Mask[any](nil) = %#v, want nil", masked)
	}
}
