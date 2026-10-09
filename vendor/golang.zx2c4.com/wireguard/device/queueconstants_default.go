//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	// LOCAL PATCH (PillowForrT): upstream is (1<<16)-1. Every packet buffer is MaxSegmentSize bytes and each receive routine holds a batch of 128, so the idle tunnel pinned
	// 25 MB of a 48 MB budget; 1700 (what the iOS build uses) brings it to under 1 MB. Safe only while no UDP GRO is in play (the box runs kernel 3.18; GRO needs 5.0+).
	// `go mod vendor` would undo this: reapply it.
	MaxSegmentSize             = 1700
	PreallocatedBuffersPerPool = 0             // Disable and allow for infinite memory growth
)
