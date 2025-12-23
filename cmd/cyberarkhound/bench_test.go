package main

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

func BenchmarkAppendDynamic(b *testing.B) {
	// Create a sample account to append
	acc := models.Account{
		ID:       "12345",
		Name:     "TestAccount",
		Address:  "10.0.0.1",
		UserName: "admin",
		SafeName: "TestSafe",
		PlatformAccountProperties: map[string]interface{}{
			"Prop1": "Value1",
			"Prop2": "Value2",
		},
	}

	count := 10000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate the workload: appending 10000 items
		// This mimics the loop in main.go
		var accounts []models.Account
		for j := 0; j < count; j++ {
			accounts = append(accounts, acc)
		}
	}
}

func BenchmarkAppendPreAlloc(b *testing.B) {
	acc := models.Account{
		ID:       "12345",
		Name:     "TestAccount",
		Address:  "10.0.0.1",
		UserName: "admin",
		SafeName: "TestSafe",
		PlatformAccountProperties: map[string]interface{}{
			"Prop1": "Value1",
			"Prop2": "Value2",
		},
	}

	count := 10000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Pre-allocate
		accounts := make([]models.Account, 0, count)
		for j := 0; j < count; j++ {
			accounts = append(accounts, acc)
		}
	}
}
