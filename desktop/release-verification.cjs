const { createHash, createPublicKey, verify } = require("node:crypto");
const { open, readFile } = require("node:fs/promises");
const { constants, lstatSync, readFileSync } = require("node:fs");
const path = require("node:path");
const REPOSITORY = "it64070092/OmniBunn-Releases";
const MAX_MANIFEST_BYTES = 65536;

function releaseSigningBytes(payload, keyId) {
  return Buffer.from(`omnibunn-release-v1\0${keyId}\0${JSON.stringify(payload)}`);
}

function validateReleasePayload(payload, repository, tag) {
  if (payload?.schemaVersion !== 1 || payload.repository !== repository || payload.tag !== tag || !/^v\d+\.\d+\.\d+$/.test(tag)
    || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(payload.sourceRevision) || !Array.isArray(payload.assets) || !payload.assets.length || payload.assets.length > 100) {
    throw new Error("Release manifest identity is invalid");
  }
  const names = new Set();
  for (const asset of payload.assets) {
    if (!asset || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(asset.name) || names.has(asset.name)
      || !Number.isSafeInteger(asset.size) || asset.size <= 0 || asset.size > 4 * 1024 ** 3 || !/^[a-f0-9]{64}$/.test(asset.sha256)) throw new Error("Release manifest asset is invalid");
    names.add(asset.name);
  }
  return payload;
}

function verifyReleaseManifest(raw, trustedKeys, repository, tag) {
  if (Buffer.byteLength(raw) > MAX_MANIFEST_BYTES) throw new Error("Release manifest exceeds size limit");
  const envelope = JSON.parse(raw), signature = envelope.signature;
  if (signature?.algorithm !== "Ed25519" || !/^[A-Za-z0-9._-]{1,64}$/.test(signature.keyId) || !Object.hasOwn(trustedKeys, signature.keyId)) throw new Error("Release signing key is not trusted");
  const key = createPublicKey(trustedKeys[signature.keyId]);
  const bytes = Buffer.from(String(signature.value || ""), "base64");
  if (key.asymmetricKeyType !== "ed25519" || bytes.length !== 64 || bytes.toString("base64") !== signature.value
    || !verify(null, releaseSigningBytes(envelope.payload, signature.keyId), key, bytes)) throw new Error("Release signature verification failed");
  return validateReleasePayload(envelope.payload, repository, tag);
}

async function verifyReleaseAsset(payload, file, name) {
  const asset = payload.assets.find((item) => item.name === name);
  if (!asset) throw new Error("Release asset is not signed");
  if (!lstatSync(file).isFile()) throw new Error("Release asset must be a regular file");
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size !== asset.size) throw new Error("Release asset size mismatch");
    const hash = createHash("sha256");
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await handle.stat(), current = lstatSync(file);
    if (hash.digest("hex") !== asset.sha256 || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || current.ino !== before.ino || current.dev !== before.dev || !current.isFile()) throw new Error("Release asset checksum or identity mismatch");
  } finally { await handle.close(); }
}

async function fetchReleaseManifest(version, request = fetch) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error("Invalid update version");
  const response = await request(`https://github.com/${REPOSITORY}/releases/download/v${version}/release-manifest.json`, { signal: AbortSignal.timeout(15000) });
  if (!response.ok || !response.body) throw new Error("Signed release manifest is unavailable");
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_MANIFEST_BYTES) throw new Error("Release manifest exceeds size limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

module.exports = { REPOSITORY, MAX_MANIFEST_BYTES, releaseSigningBytes, validateReleasePayload, verifyReleaseManifest, verifyReleaseAsset, fetchReleaseManifest };

if (require.main === module) {
  (async () => {
    const [manifest, repository, tag, name, file] = process.argv.slice(2);
    const legacy = JSON.parse(readFileSync(path.join(__dirname, "release-legacy.json"), "utf8"));
    if (!(repository === REPOSITORY && Object.hasOwn(legacy, tag)) && lstatSync(manifest).size > MAX_MANIFEST_BYTES) throw new Error("Release manifest exceeds size limit");
    // A reviewed, compiled-in rollback baseline is the only unsigned exception.
    const payload = repository === REPOSITORY && Object.hasOwn(legacy, tag) ? legacy[tag]
      : verifyReleaseManifest(await readFile(manifest, "utf8"), JSON.parse(readFileSync(path.join(__dirname, "release-trust.json"), "utf8")), repository, tag);
    await verifyReleaseAsset(payload, file, name);
    process.stdout.write("Release signature/pinned baseline and package bytes verified\n");
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
