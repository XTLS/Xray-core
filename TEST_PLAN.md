# XPool Test Plan

## 1. Objectives
Verify XPool protocol stability, performance, and fault tolerance under harsh network conditions.

## 2. Test Environment
*   **Infrastructure**: `common/xpool/sim` (In-memory network simulator).
*   **Components**: `FaultyConn` (injects Latency, Jitter, Blackhole, RST).

## 3. Test Scenarios

### 3.1 Basic Connectivity
*   **Goal**: Ensure Client can talk to Server over ideal connection.
*   **Steps**:
    1.  Setup VirtualNetwork.
    2.  Client sends "Hello".
    3.  Server echos "Hello".
    4.  Verify data match.

### 3.2 High Latency (RTT)
*   **Goal**: Verify throughput and handshake stability with high latency.
*   **Config**: Latency=200ms, Jitter=50ms.
*   **Steps**: Transfer 1MB file.
*   **Check**: Transfer completes.

### 3.3 Connection Reset (RST) Attack
*   **Goal**: Verify Session Migration.
*   **Config**: RSTProb=0.01 (1% chance per write).
*   **Steps**:
    1.  Start transfer (10MB).
    2.  Wait for random RST.
    3.  Client should dial new connection and resume.
*   **Check**: Transfer completes with full data integrity.

### 3.4 Connection Stall (Blackhole)
*   **Goal**: Verify Timeout detection and Migration.
*   **Config**: Toggle `Blackhole=true` for 5s, then `Blackhole=false` (or Client migrates to new conn).
*   **Steps**:
    1.  Start transfer.
    2.  Simulate stall (drop all packets).
    3.  Client should detect timeout (>3s) and migrate.
*   **Check**: Client recovers.

### 3.5 Resource Usage (Stress)
*   **Goal**: Detect memory leaks or high CPU.
*   **Config**: 100 concurrent sessions.
*   **Steps**: Run for 30s.
*   **Check**: `go test -bench` results.

## 4. Execution
Run `go test -v ./common/xpool/integration_test.go`.
