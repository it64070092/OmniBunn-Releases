import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, lstatSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const runGh = (args) => execFileSync("gh", args, { encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 300_000 });

function release(repository, tag, gh) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !/^v\d+\.\d+\.\d+$/.test(tag)) throw new Error("Invalid release repository or tag");
  const value = JSON.parse(gh(["api", `repos/${repository}/releases/tags/${tag}`]));
  if (value.tag_name !== tag || typeof value.draft !== "boolean" || !Array.isArray(value.assets)) throw new Error("Invalid release metadata");
  return value;
}

export function assertDraftRelease(repository, tag, gh = runGh) {
  const value = release(repository, tag, gh);
  if (!value.draft) throw new Error(`Published release ${tag} cannot be changed; create a new version`);
  return value;
}

export async function uploadReleaseAssets(repository, tag, inputs, gh = runGh) {
  const value = release(repository, tag, gh);
  const pending = [], names = new Set();
  for (const input of inputs) {
    const [path, label] = input.split("#", 2);
    const file = resolve(path), name = basename(file), stat = lstatSync(file);
    if (!stat.isFile() || stat.size === 0 || names.has(name)) throw new Error(`Invalid or duplicate release asset: ${name}`);
    names.add(name);
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(file)) hash.update(chunk);
    const existing = value.assets.filter((asset) => asset.name === name);
    if (existing.length) {
      if (existing.length !== 1 || existing[0].state !== "uploaded" || existing[0].size !== stat.size || existing[0].digest !== `sha256:${hash.digest("hex")}`) {
        throw new Error(`Existing release asset differs or has no verified digest: ${name}; refusing overwrite`);
      }
    } else pending.push(label ? `${file}#${label}` : file);
  }
  // Read-only reruns can verify identical published assets. Every mutation needs
  // a draft, and gh's default conflict handling protects competing uploads.
  if (pending.length) {
    assertDraftRelease(repository, tag, gh);
    gh(["release", "upload", tag, "--repo", repository, ...pending]);
  }
}

export function publishRelease(repository, tag, gh = runGh) {
  if (release(repository, tag, gh).draft) gh(["release", "edit", tag, "--repo", repository, "--draft=false", "--latest"]);
}

export function assertReleaseSource(repository, tag, revision, gh = runGh) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !/^v\d+\.\d+\.\d+$/.test(tag) || !/^[a-f0-9]{40}$/.test(revision)) throw new Error("Invalid release source identity");
  let object = JSON.parse(gh(["api", `repos/${repository}/git/ref/tags/${tag}`])).object;
  for (let depth = 0; object?.type === "tag" && depth < 4; depth++) {
    if (!/^[a-f0-9]{40}$/.test(object.sha)) throw new Error("Invalid annotated release tag");
    object = JSON.parse(gh(["api", `repos/${repository}/git/tags/${object.sha}`])).object;
  }
  if (object?.type !== "commit" || object.sha !== revision) throw new Error("Release tag moved from the build commit");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, repository, tag, ...inputs] = process.argv.slice(2);
  if (command === "assert-draft") assertDraftRelease(repository, tag);
  else if (command === "upload" && inputs.length) await uploadReleaseAssets(repository, tag, inputs);
  else if (command === "publish") publishRelease(repository, tag);
  else if (command === "check-source") assertReleaseSource(repository, tag, inputs[0]);
  else throw new Error("Usage: release-assets.mjs assert-draft|upload|publish OWNER/REPO vX.Y.Z [assets...]");
}
