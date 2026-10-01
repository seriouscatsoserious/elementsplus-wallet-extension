import { lstat } from "node:fs/promises";
import path from "node:path";

// Build commands replace generated directories. An environment override must
// never turn that cleanup into deletion of source, a home directory, or keys.
export async function generatedDirectory(root, candidate, allowed) {
  const resolved = path.resolve(candidate);
  if (!allowed.some((relative) => path.join(root, relative) === resolved)) {
    throw new Error("Build output must be one of the repository's generated directories");
  }
  let current = root;
  for (const component of path.relative(root, resolved).split(path.sep)) {
    current = path.join(current, component);
    try {
      if ((await lstat(current)).isSymbolicLink()) {
        throw new Error("Build output and its parents must not be symbolic links");
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return resolved;
}
