// Composition spike, shared assertions: drives the wac-composed
// component (Rust adapter + componentize-go engine) through its
// driver exports. Used by the node and browser legs.

export async function assertComposeProbe(driver) {
  const eq = (a, b, what) => {
    if (a !== b) throw new Error(`${what}: ${a} !== ${b}`);
  };

  // Cross-component function call, through the fused boundary.
  const version = driver.versionViaEngine();
  if (!version.includes("mosh-go v0.5.3-0.20260405220648-8dca5c67ec8e")) {
    throw new Error(`unexpected engine version through composition: ${version}`);
  }

  // Resource construct + methods + drop across the boundary.
  const report = driver.sessionRoundTrip("AAAAAAAAAAAAAAAAAAAAAA", 80, 24);
  eq(report.datagrams, 2, "datagrams (association + keystroke state)");
  eq(report.sentNum, 1n, "sent-num");
  if (!(report.firstDatagramLen > 24 && report.firstDatagramLen < 200)) {
    throw new Error(`implausible first datagram len: ${report.firstDatagramLen}`);
  }

  // Error propagation from the engine through the adapter.
  let threw = null;
  try {
    driver.sessionRoundTrip("notakey!", 80, 24);
  } catch (e) {
    threw = e;
  }
  if (!threw) throw new Error("bad key did not error through composition");
  const msg = String(threw.payload ?? threw.message ?? threw);
  if (!msg.includes("bad key")) throw new Error(`unexpected bad-key error: ${msg}`);

  return `OK (version=${version.slice(0, 30)}…, first-dgram=${report.firstDatagramLen}B)`;
}
