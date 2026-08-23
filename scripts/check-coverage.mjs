import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const [resultsDirectory = "TestResults", targetArgument = "0.75"] = process.argv.slice(2);
const target = Number(targetArgument);

if (!Number.isFinite(target) || target <= 0 || target > 1) {
  throw new Error("Coverage target must be a decimal value greater than 0 and at most 1.");
}

const coverageFiles = await findCoverageFiles(resultsDirectory);
if (coverageFiles.length === 0) {
  throw new Error(`No Cobertura coverage file was found under ${resultsDirectory}.`);
}

const rates = await Promise.all(coverageFiles.map(readLineRate));
const lineRate = rates.reduce((sum, rate) => sum + rate, 0) / rates.length;
const percent = (lineRate * 100).toFixed(2);
const targetPercent = (target * 100).toFixed(0);

console.log(`Line coverage: ${percent}% (target: ${targetPercent}%)`);
if (lineRate < target) {
  throw new Error(`Line coverage ${percent}% is below the ${targetPercent}% MVP target.`);
}

async function findCoverageFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return findCoverageFiles(path);
    }

    return entry.name === "coverage.cobertura.xml" ? [path] : [];
  }));

  return nested.flat();
}

async function readLineRate(file) {
  const xml = await readFile(file, "utf8");
  const match = xml.match(/<coverage\b[^>]*\bline-rate="([0-9.]+)"/);
  if (!match) {
    throw new Error(`No line-rate was found in ${file}.`);
  }

  return Number(match[1]);
}
