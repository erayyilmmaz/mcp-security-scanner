import { readdir, readFile } from "node:fs/promises";
import { resolve, join, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";

const sourceExtensions = new Set([".cs", ".csproj", ".js", ".mjs", ".json"]);
const ignoredDirectories = new Set(["bin", "obj"]);

const forbiddenPatterns = [
  {
    id: "PROCESS_API",
    expression: /\b(?:System\.Diagnostics\.Process|Process\.Start|ProcessStartInfo)\b/
  },
  {
    id: "JAVASCRIPT_PROCESS_API",
    expression: /\b(?:child_process|Deno\.Command|Bun\.spawn)\b|\b(?:exec|execFile|spawn|fork)\s*\(/
  },
  {
    id: "GIT_LIBRARY",
    expression: /\bLibGit2Sharp\b/
  },
  {
    id: "REPOSITORY_EXECUTION_COMMAND",
    expression: /\b(?:git\s+(?:clone|checkout)|npm\s+(?:ci|install|run)|yarn\s+(?:install|run)|pnpm\s+(?:install|run)|pip3?\s+install|dotnet\s+(?:run|build|test)|docker\s+(?:build|run))\b/i
  }
];

export async function collectSourceFiles(sourceRoot) {
  const absoluteRoot = resolve(sourceRoot);
  const files = [];

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      const path = join(directory, entry.name);

      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) {
          await visit(path);
        }

        continue;
      }

      if (entry.isFile() && sourceExtensions.has(extname(entry.name))) {
        files.push({
          path: relative(absoluteRoot, path),
          content: await readFile(path, "utf8")
        });
      }
    }
  }

  await visit(absoluteRoot);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

export function findBoundaryViolations(files) {
  return files.flatMap((file) =>
    forbiddenPatterns.flatMap((pattern) => {
      const match = pattern.expression.exec(file.content);
      if (match === null) {
        return [];
      }

      const line = file.content.slice(0, match.index).split("\n").length;
      return [{ path: file.path, line, patternId: pattern.id, evidence: match[0] }];
    }));
}

async function main() {
  const sourceRoot = process.argv[2] ?? "src";
  const files = await collectSourceFiles(sourceRoot);
  const violations = findBoundaryViolations(files);

  if (violations.length === 0) {
    console.log(`No repository-execution primitives found in ${files.length} application source files.`);
    return;
  }

  console.error("No-execution scanner boundary violation(s) found:");
  for (const violation of violations) {
    console.error(`- ${violation.path}:${violation.line} [${violation.patternId}] ${violation.evidence}`);
  }

  process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
