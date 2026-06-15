package memory_test

import (
	"testing"

	"github.com/elloloop/workspace/internal/repo/conformance"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

func TestMemoryConformance(t *testing.T) {
	conformance.Run(t, func() service.Repository { return memory.New() })
}
