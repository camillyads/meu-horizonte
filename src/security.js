import bcrypt from "bcryptjs";

export function normalizeNameToken(value) {
  return String(value || "")
    .trim()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]/g, "")
    .toUpperCase();
}

export function firstNameFromFullName(fullName) {
  const parts = String(fullName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  return parts.length ? parts[0] : "";
}

export function buildStudentLogin({ classCode, fullName }) {
  const firstName = normalizeNameToken(firstNameFromFullName(fullName));
  const turma = normalizeNameToken(classCode);
  return `${turma}${firstName}`;
}

export function generateStudentPassword() {
  const letters = "abcdefghijklmnopqrstuvwxyz";
  const a = letters[Math.floor(Math.random() * letters.length)];
  const b = letters[Math.floor(Math.random() * letters.length)];
  return `2016${a}${b}`;
}

export function hashPassword(plain) {
  return bcrypt.hashSync(String(plain), 10);
}

export function verifyPassword(plain, hash) {
  return bcrypt.compareSync(String(plain), String(hash));
}
