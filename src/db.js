import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const projectRoot = path.resolve(process.cwd());
const dataDir = path.join(projectRoot, "data");
const dbPath = path.join(dataDir, "db.json");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function nowIso() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function atomicWriteJson(filePath, value) {
  const dir = path.dirname(filePath);
  ensureDir(dir);
  const tmpPath = path.join(dir, `${path.basename(filePath)}.${crypto.randomUUID()}.tmp`);
  fs.writeFileSync(tmpPath, JSON.stringify(value, null, 2), "utf8");
  fs.renameSync(tmpPath, filePath);
}

export function getDbFilePath() {
  return dbPath;
}

export function loadDb() {
  ensureDir(dataDir);
  if (!fs.existsSync(dbPath)) {
    return null;
  }
  const raw = fs.readFileSync(dbPath, "utf8");
  return JSON.parse(raw);
}

export function saveDb(db) {
  atomicWriteJson(dbPath, db);
}

export function createEmptyDb() {
  return {
    meta: { createdAt: nowIso(), updatedAt: nowIso() },
    users: [],
    classes: [],
    activities: [],
    completions: [],
    warnings: [],
    observations: [],
    documents: [],
    infos: []
  };
}

export function touchDb(db) {
  db.meta.updatedAt = nowIso();
}

export function makeId(prefix) {
  return id(prefix);
}

export function isoNow() {
  return nowIso();
}
