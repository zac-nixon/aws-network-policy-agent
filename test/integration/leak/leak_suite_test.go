package leak

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-network-policy-agent/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	fw        *framework.Framework
	ctx       context.Context
	namespace = "leak-test"

	// preserveEnv is flipped to true by a spec that reproduces the leak. It tells ALL teardown
	// paths — the spec's DeferCleanups, the churn goroutines, AND this suite's AfterSuite — to
	// leave the reproduction environment (namespace, pods, probes, maps) in place for inspection.
	preserveEnv atomic.Bool
)

func TestBPFProbeLeakOnPodChurn(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BPF Probe Leak Test Suite")
}

var _ = BeforeSuite(func() {
	fw = framework.New(framework.GlobalOptions)
	ctx = context.Background()

	err := fw.NamespaceManager.CreateNamespace(ctx, namespace)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	if preserveEnv.Load() {
		GinkgoWriter.Printf("Leak detected: PRESERVING namespace %q and all its resources for inspection. "+
			"Clean up manually with: kubectl delete namespace %s\n", namespace, namespace)
		return
	}
	//err := fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, namespace)
	//Expect(err).ToNot(HaveOccurred())
})
