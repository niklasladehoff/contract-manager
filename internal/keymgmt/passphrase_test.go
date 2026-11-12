// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keymgmt

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

func TestGenerationPassphraseErrors(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"empty", "", "required"},
		{"blank", "   ", "required"},
		{"short", "Short!1", "at least 12"},
		{"padding cannot satisfy length", "     Short!1     ", "at least 12"},
		{"padding cannot satisfy special character", " LongPassword12 ", "special character"},
		{"no uppercase", "longpassword!1", "uppercase"},
		{"no lowercase", "LONGPASSWORD!1", "lowercase"},
		{"no digit", "LongPassword!!", "digit"},
		{"no special", "LongPassword12", "special character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGenerationPassphrase(model.BuildKeyModeGenerate, &tc.value)
			var appErr *model.AppError
			if !errors.As(err, &appErr) || appErr.HTTPStatus != http.StatusBadRequest || !strings.Contains(appErr.Message, tc.want) {
				t.Fatalf("expected actionable client error, got %v", err)
			}
			if strings.Contains(appErr.Message, tc.value) && strings.TrimSpace(tc.value) != "" {
				t.Fatal("error includes supplied passphrase")
			}
		})
	}
	if err := ValidateGenerationPassphrase(model.BuildKeyModeGenerate, nil); err == nil {
		t.Fatal("nil passphrase accepted")
	}
	if err := ValidateGenerationPassphrase(model.BuildKeyModeUploadPublic, nil); err != nil {
		t.Fatal(err)
	}
	value := "  Correct!Passphrase2026  "
	original := value
	if err := ValidateGenerationPassphrase(model.BuildKeyModeGenerate, &value); err != nil {
		t.Fatal(err)
	}
	if value != original {
		t.Fatal("passphrase was modified")
	}
}

func TestNormalizePassphrase(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" \t\r\nSecret! With spaces2026\u00a0\ufeff", "Secret! With spaces2026"},
		{"\u0085Secret!2026\u0085", "\u0085Secret!2026\u0085"},
		{"\ufeff\u2028\u2029\u3000", ""},
	} {
		if got := NormalizePassphrase(tc.input); got != tc.want {
			t.Fatalf("normalization does not match JavaScript whitespace rules")
		}
	}
}
