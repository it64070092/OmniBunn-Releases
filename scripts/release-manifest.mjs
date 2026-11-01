import { createHash, createPrivateKey, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createReadStream, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import verification from "../desktop/release-verification.cjs";
import { assertDraftRelease, uploadReleaseAssets } from "./release-assets.mjs";
const { REPOSITORY, MAX_MANIFEST_BYTES, releaseSigningBytes, validateReleasePayload, verifyReleaseManifest } = verification;
const gh = (args) => execFileSync("gh", args, { encoding: "utf8", maxBuffer: MAX_MANIFEST_BYTES, timeout: 30_000 });
const trust = () => JSON.parse(readFileSync(new URL("../desktop/release-trust.json", import.meta.url), "utf8"));

export async function describeAssets(files) {
  const assets = [];
  for (const file of files) {
    const stat = lstatSync(file);
    if (!stat.isFile()) throw new Error("Release asset must be a regular file");
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(file)) hash.update(chunk);
    assets.push({ name: basename(file), size: stat.size, sha256: hash.digest("hex") });
  }
  return assets.sort((a, b) => a.name.localeCompare(b.name, "en"));
}

export function signCandidate(raw, key, trustedKeys, keyId = "omnibunn-release-2026-11") {
  if (Buffer.byteLength(raw) > MAX_MANIFEST_BYTES) throw new Error("Release candidate exceeds size limit");
  const payload = JSON.parse(raw);
  validateReleasePayload(payload, REPOSITORY, payload.tag);
  const version = payload.tag.slice(1);
  for (const name of [`omnibunn-control_${version}_amd64.deb`, `dbops-control_${version}_amd64.deb`, `OmniBunn-Setup-${version}-x64.exe`, "latest.yml", "SHA256SUMS", "SHA256SUMS.windows", "install.sh"]) {
    if (!payload.assets.some((asset) => asset.name === name)) throw new Error(`Release candidate is incomplete: ${name}`);
  }
  const privateKey = createPrivateKey(key);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Release signing requires Ed25519");
  const envelope = { payload, signature: { algorithm: "Ed25519", keyId, value: sign(null, releaseSigningBytes(payload, keyId), privateKey).toString("base64") } };
  const signed = JSON.stringify(envelope, null, 2) + "\n";
  verifyReleaseManifest(signed, trustedKeys, REPOSITORY, payload.tag);
  return signed;
}

export async function signDraftRelease(tag, revision, candidateSha, key, trustedKeys, run = gh) {
  const release = assertDraftRelease(REPOSITORY, tag, run);
  const candidate = release.assets.find((asset) => asset.name === "release-candidate.json");
  if (!candidate || !Number.isSafeInteger(candidate.id) || candidate.size > MAX_MANIFEST_BYTES || !/^[a-f0-9]{64}$/.test(candidateSha)) throw new Error("Release candidate is missing or invalid");
  const raw = run(["api", `repos/${REPOSITORY}/releases/assets/${candidate.id}`, "-H", "Accept: application/octet-stream"]);
  if (createHash("sha256").update(raw).digest("hex") !== candidateSha) throw new Error("Release candidate differs from the approved build");
  const payload = validateReleasePayload(JSON.parse(raw), REPOSITORY, tag);
  if (payload.sourceRevision !== revision) throw new Error("Release source commit differs from the approved build");
  for (const asset of payload.assets) {
    const uploaded = release.assets.filter((item) => item.name === asset.name);
    if (uploaded.length !== 1 || uploaded[0].state !== "uploaded" || uploaded[0].size !== asset.size || uploaded[0].digest !== `sha256:${asset.sha256}`) throw new Error(`Uploaded bytes do not match the build: ${asset.name}`);
  }
  const dir = mkdtempSync(join(tmpdir(), "omnibunn-release-signing-"));
  try {
    const file = join(dir, "release-manifest.json");
    writeFileSync(file, signCandidate(raw, key, trustedKeys), { mode: 0o600, flag: "wx" });
    await uploadReleaseAssets(REPOSITORY, tag, [file], run);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, ...args] = process.argv.slice(2);
  if (command === "assets") process.stdout.write(JSON.stringify(await describeAssets(args)) + "\n");
  else if (command === "candidate") {
    const [tag, sourceRevision] = args;
    const payload = { schemaVersion: 1, repository: REPOSITORY, tag, sourceRevision, assets: [...JSON.parse(process.env.NATIVE_ASSETS), ...JSON.parse(process.env.WINDOWS_ASSETS)].sort((a, b) => a.name.localeCompare(b.name, "en")) };
    validateReleasePayload(payload, REPOSITORY, tag);
    process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
  } else if (command === "sign") {
    await signDraftRelease(...args, process.env.OMNIBUNN_RELEASE_SIGNING_KEY, trust());
  } else if (command === "request-signature") {
    const candidatePath = args[0], raw = readFileSync(candidatePath, "utf8"), candidate = JSON.parse(raw);
    validateReleasePayload(candidate, REPOSITORY, candidate.tag);
    const sha = createHash("sha256").update(raw).digest("hex");
    gh(["workflow", "run", "sign-release.yml", "--repo", REPOSITORY, "--ref", "main", "-f", `tag=${candidate.tag}`, "-f", `source_revision=${candidate.sourceRevision}`, "-f", `candidate_sha256=${sha}`]);
    console.log("Waiting for approval in the public release-signing environment; no release has been published.");
    for (let attempt = 0; attempt < 180; attempt++) {
      const staged = assertDraftRelease(REPOSITORY, candidate.tag, gh);
      const asset = staged.assets.find((item) => item.name === "release-manifest.json");
      if (asset) {
        if (!Number.isSafeInteger(asset.id) || asset.size > MAX_MANIFEST_BYTES) throw new Error("Invalid signed manifest asset");
        const signed = gh(["api", `repos/${REPOSITORY}/releases/assets/${asset.id}`, "-H", "Accept: application/octet-stream"]);
        const verified = verifyReleaseManifest(signed, trust(), REPOSITORY, candidate.tag);
        if (JSON.stringify(verified) !== JSON.stringify(candidate)) throw new Error("Signed manifest does not match this build");
        process.stdout.write("Approved release signature verified\n");
        break;
      }
      if (attempt === 179) throw new Error("Release signing approval timed out; release remains a draft");
      await new Promise((resolve) => setTimeout(resolve, 15000));
    }
  } else throw new Error("Usage: release-manifest.mjs assets|candidate|sign|request-signature ...");
}
