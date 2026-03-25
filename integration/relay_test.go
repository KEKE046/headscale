package integration

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestPeerRelayCapGrantInPacketFilter verifies that headscale correctly includes
// relay CapGrant rules in every client's PacketFilter (via MapResponse), and that
// clients receive both PeerCapabilityRelay and PeerCapabilityRelayTarget capabilities.
//
// The headscale server injects a universal CapGrant rule in hscontrol/policy/v2/filter.go
// (relayCapGrantRule) so that every node in a tailnet can act as a relay candidate and
// relay target.  This test validates that the rule survives the full pipeline:
// policy evaluation → mapper → MapResponse → client PacketFilter.
func TestPeerRelayCapGrantInPacketFilter(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("relaycapgrant"),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// Verify that each client's PacketFilter contains relay capabilities.
	// PacketFilter() requires Tailscale 1.56+; older clients are skipped.
	for _, client := range allClients {
		client := client // capture loop variable

		if !util.TailscaleVersionNewerOrEqual("1.56", client.Version()) {
			t.Logf("skipping PacketFilter check for %q (version %q < 1.56)", client.Hostname(), client.Version())
			continue
		}

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			matches, err := client.PacketFilter()
			assert.NoError(c, err, "PacketFilter() failed for %q", client.Hostname())

			hasRelayMatch := false
			hasRelayTargetMatch := false

			for _, match := range matches {
				for _, cap := range match.Caps {
					if cap.Cap == tailcfg.PeerCapabilityRelay {
						hasRelayMatch = true
					}
					if cap.Cap == tailcfg.PeerCapabilityRelayTarget {
						hasRelayTargetMatch = true
					}
				}
			}

			assert.True(c, hasRelayMatch,
				"PacketFilter of %q should contain PeerCapabilityRelay (%q)",
				client.Hostname(), tailcfg.PeerCapabilityRelay)
			assert.True(c, hasRelayTargetMatch,
				"PacketFilter of %q should contain PeerCapabilityRelayTarget (%q)",
				client.Hostname(), tailcfg.PeerCapabilityRelayTarget)
		}, 30*time.Second, 500*time.Millisecond,
			"relay CapGrant should be present in PacketFilter for %q", client.Hostname())
	}
}

// TestPeerRelayServerDiscovery verifies the end-to-end relay server workflow:
//
//  1. Three nodes join a tailnet (A, B as relay server, C as peer).
//  2. Node B enables its relay server on UDP port 40000.
//  3. We confirm B's relay server is running (via `tailscale debug peer-relay-sessions`).
//  4. Nodes A and C can still ping each other (basic connectivity remains intact after
//     relay server activation).
//
// The `tailscale debug peer-relay-sessions` subcommand and the
// `tailscale set --relay-server-port` flag were introduced in newer Tailscale builds.
// Older clients that lack these commands are skipped gracefully.
func TestPeerRelayServerDiscovery(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 3,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("relayserverdiscovery"),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	require.GreaterOrEqualf(t, len(allClients), 3,
		"need at least 3 clients for relay server discovery test, got %d", len(allClients))

	clientA := allClients[0]
	relayServer := allClients[1] // node B acts as the relay server
	clientC := allClients[2]

	// The relay server commands require a recent HEAD build.  If the chosen
	// relay server node is not running a sufficiently new version, skip.
	if !util.TailscaleVersionNewerOrEqual("1.56", relayServer.Version()) {
		t.Skipf("relay server node %q has version %q which does not support relay server commands (need 1.56+)",
			relayServer.Hostname(), relayServer.Version())
	}

	// Enable the relay server on node B.
	// This is a blocking state-change command and must NOT be wrapped in
	// EventuallyWithT (per AGENTS.md: blocking operations must not be wrapped).
	_, _, err = relayServer.Execute([]string{
		"tailscale", "set", "--relay-server-port=40000",
	})
	require.NoErrorf(t, err,
		"failed to enable relay server on %q", relayServer.Hostname())

	// Confirm that the relay server on B is up and listening.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		out, _, err := relayServer.Execute([]string{
			"tailscale", "debug", "peer-relay-sessions",
		})
		assert.NoError(c, err,
			"tailscale debug peer-relay-sessions failed on %q", relayServer.Hostname())
		assert.Contains(c, out, "40000",
			"relay server on %q should report port 40000 in peer-relay-sessions output",
			relayServer.Hostname())
	}, 30*time.Second, 500*time.Millisecond,
		"relay server should be running on %q (port 40000)", relayServer.Hostname())

	// Verify that A and C still see relay capability in their PacketFilters now
	// that B has registered as a relay server.  Both must be running 1.56+.
	for _, client := range []TailscaleClient{clientA, clientC} {
		client := client // capture loop variable

		if !util.TailscaleVersionNewerOrEqual("1.56", client.Version()) {
			t.Logf("skipping PacketFilter relay cap check for %q (version %q < 1.56)",
				client.Hostname(), client.Version())
			continue
		}

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			matches, err := client.PacketFilter()
			assert.NoError(c, err,
				"PacketFilter() failed for %q", client.Hostname())

			hasRelayCap := false

			for _, match := range matches {
				for _, cap := range match.Caps {
					if cap.Cap == tailcfg.PeerCapabilityRelay ||
						cap.Cap == tailcfg.PeerCapabilityRelayTarget {
						hasRelayCap = true
					}
				}
			}

			assert.True(c, hasRelayCap,
				"PacketFilter of %q should contain relay capabilities after B registered as relay server",
				client.Hostname())
		}, 30*time.Second, 500*time.Millisecond,
			"relay capabilities should be visible in PacketFilter for %q", client.Hostname())
	}

	// Verify that basic connectivity between A and C still works after the relay
	// server has been activated on B.  Connectivity may go via DERP or direct;
	// both are acceptable here.
	relayServerIP, err := relayServer.IPv4()
	require.NoErrorf(t, err, "getting IPv4 of relay server %q", relayServer.Hostname())

	clientAIP, err := clientA.IPv4()
	require.NoErrorf(t, err, "getting IPv4 of clientA %q", clientA.Hostname())

	clientCIP, err := clientC.IPv4()
	require.NoErrorf(t, err, "getting IPv4 of clientC %q", clientC.Hostname())

	// A pings B (relay server). Accept any path (direct or DERP).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := clientA.Ping(relayServerIP.String(),
			tsic.WithPingTimeout(2*time.Second),
			tsic.WithPingCount(3),
		)
		assert.NoError(c, err,
			"%q should be able to ping relay server %q (%s)",
			clientA.Hostname(), relayServer.Hostname(), relayServerIP)
	}, 30*time.Second, 500*time.Millisecond,
		"clientA should be able to ping the relay server node B")

	// A pings C. Accept any path (direct or DERP).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := clientA.Ping(clientCIP.String(),
			tsic.WithPingTimeout(2*time.Second),
			tsic.WithPingCount(3),
		)
		assert.NoError(c, err,
			"%q should be able to ping %q (%s) even after relay server is active",
			clientA.Hostname(), clientC.Hostname(), clientCIP)
	}, 30*time.Second, 500*time.Millisecond,
		"clientA should be able to ping clientC after relay server activation")

	// C pings A. Accept any path (direct or DERP).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := clientC.Ping(clientAIP.String(),
			tsic.WithPingTimeout(2*time.Second),
			tsic.WithPingCount(3),
		)
		assert.NoError(c, err,
			"%q should be able to ping %q (%s) even after relay server is active",
			clientC.Hostname(), clientA.Hostname(), clientAIP)
	}, 30*time.Second, 500*time.Millisecond,
		"clientC should be able to ping clientA after relay server activation")
}
