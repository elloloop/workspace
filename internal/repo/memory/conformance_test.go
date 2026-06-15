package memory_test

import (
	"testing"

	"github.com/elloloop/workspaces/internal/repo/conformance"
	"github.com/elloloop/workspaces/internal/repo/memory"
	"github.com/elloloop/workspaces/internal/service"
)

func TestMemoryConformance(t *testing.T) {
	conformance.Run(t, func() service.Repository { return memory.New() })
}
