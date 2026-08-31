package helpers

import (
	"testing"

	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	corev1 "k8s.io/api/core/v1"
)

// mcp builds a MachineConfigPool with the given machine counts and rendered
// config names for status/spec.
func mcp(
	machineCount, updated, unavailable, degraded int32,
	specConfig, statusConfig string,
) *mcfgv1.MachineConfigPool {
	return &mcfgv1.MachineConfigPool{
		Spec: mcfgv1.MachineConfigPoolSpec{
			Configuration: mcfgv1.MachineConfigPoolStatusConfiguration{
				ObjectReference: corev1.ObjectReference{Name: specConfig},
			},
		},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:            machineCount,
			UpdatedMachineCount:     updated,
			UnavailableMachineCount: unavailable,
			DegradedMachineCount:    degraded,
			Configuration: mcfgv1.MachineConfigPoolStatusConfiguration{
				ObjectReference: corev1.ObjectReference{Name: statusConfig},
			},
		},
	}
}

// TestIsMachineConfigPoolUpdated covers the completion predicate, including the
// CMP-4631 addition that a pool mid-rollout (its targeted rendered config not
// yet realized in status) is not reported as updated even when the machine
// counts momentarily look settled.
func TestIsMachineConfigPoolUpdated(t *testing.T) {
	const rendered = "rendered-worker-abc"
	tests := []struct {
		name string
		pool *mcfgv1.MachineConfigPool
		want bool
	}{
		{
			name: "fully converged and config realized",
			pool: mcp(1, 1, 0, 0, rendered, rendered),
			want: true,
		},
		{
			name: "mid-rollout: spec config not yet realized in status",
			pool: mcp(3, 3, 0, 0, "rendered-worker-new", "rendered-worker-old"),
			want: false,
		},
		{
			name: "not all machines updated",
			pool: mcp(3, 2, 1, 0, rendered, rendered),
			want: false,
		},
		{
			name: "a machine is unavailable",
			pool: mcp(3, 3, 1, 0, rendered, rendered),
			want: false,
		},
		{
			name: "a machine is degraded",
			pool: mcp(3, 3, 0, 1, rendered, rendered),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMachineConfigPoolUpdated(tt.pool); got != tt.want {
				t.Errorf("isMachineConfigPoolUpdated() = %v, want %v", got, tt.want)
			}
		})
	}
}
