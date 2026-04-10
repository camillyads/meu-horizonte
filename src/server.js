import express from "express";
import session from "express-session";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { createEmptyDb, loadDb, makeId, saveDb, touchDb, isoNow } from "./db.js";
import { buildStudentLogin, generateStudentPassword, hashPassword, normalizeNameToken, verifyPassword } from "./security.js";

const app = express();
const port = Number(process.env.PORT || 3000);

const projectRoot = path.resolve(process.cwd());
const uploadsDir = path.join(projectRoot, "uploads");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

ensureDir(uploadsDir);

app.set("view engine", "ejs");
app.set("views", path.join(projectRoot, "views"));
app.use("/public", express.static(path.join(projectRoot, "public")));
app.use("/uploads", express.static(uploadsDir));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "meu-horizonte-dev-secret",
    resave: false,
    saveUninitialized: false
  })
);

function getDb() {
  const db = loadDb();
  if (db) return db;
  const fresh = createEmptyDb();

  const teacherId = makeId("usr");
  fresh.users.push({
    id: teacherId,
    role: "teacher",
    login: "16696444726",
    passwordHash: hashPassword("654321"),
    fullName: "Professor Robson Guilherme Rodrigues",
    createdAt: isoNow()
  });

  const coordinatorId = makeId("usr");
  fresh.users.push({
    id: coordinatorId,
    role: "coordinator",
    login: "coordormanda",
    passwordHash: hashPassword("112233"),
    fullName: "Coordenação",
    createdAt: isoNow()
  });

  const classCodes = ["1LOG1", "1LOG2", "1RDC1", "1RDC2", "1RDC3"];
  for (const code of classCodes) {
    fresh.classes.push({
      id: makeId("cls"),
      code,
      name: code,
      createdAt: isoNow()
    });
  }

  const class1rdc1 = fresh.classes.find((c) => c.code === "1RDC1");
  if (class1rdc1) {
    const studentId = makeId("usr");
    fresh.users.push({
      id: studentId,
      role: "student",
      login: "1RDC1LUIZ",
      passwordHash: hashPassword("2016ax"),
      fullName: "LUIZ FERNANDO",
      firstName: "LUIZ",
      classId: class1rdc1.id,
      createdAt: isoNow()
    });
  }

  saveDb(fresh);
  return fresh;
}

function writeDb(mutator) {
  const db = getDb();
  mutator(db);
  touchDb(db);
  saveDb(db);
}

function getUserById(db, userId) {
  return db.users.find((u) => u.id === userId);
}

function getUserByLogin(db, login) {
  return db.users.find((u) => u.login === login);
}

function requireAuth(req, res, next) {
  const db = getDb();
  const userId = req.session.userId;
  if (!userId) return res.redirect("/login");
  const user = getUserById(db, userId);
  if (!user) return res.redirect("/login");
  req.currentUser = user;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    const user = req.currentUser;
    if (!user || user.role !== role) return res.status(403).send("Acesso negado.");
    next();
  };
}

function dashboardPathForRole(role) {
  if (role === "teacher") return "/professor";
  if (role === "coordinator") return "/coordenacao";
  return "/aluno";
}

function pageTitleForRole(role) {
  if (role === "teacher") return "Painel do Professor";
  if (role === "coordinator") return "Painel da Coordenação";
  return "Painel do Aluno";
}

function safeInt(value) {
  const n = Number.parseInt(String(value), 10);
  return Number.isFinite(n) ? n : 0;
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${crypto.randomUUID()}_${file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")}`)
  }),
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "application/pdf") return cb(new Error("Envie apenas PDF."));
    cb(null, true);
  },
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.use((req, res, next) => {
  const db = getDb();
  const user = req.session.userId ? getUserById(db, req.session.userId) : null;
  res.locals.currentUser = user;
  res.locals.pageTitle = user ? pageTitleForRole(user.role) : "Meu horizonte";
  next();
});

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const db = getDb();
  const login = String(req.body.login || "").trim();
  const password = String(req.body.password || "");
  const user = getUserByLogin(db, login);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).render("login", { error: "Login ou senha inválidos." });
  }
  req.session.userId = user.id;
  res.redirect(dashboardPathForRole(user.role));
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/aluno", requireAuth, requireRole("student"), (req, res) => {
  const db = getDb();
  const user = req.currentUser;
  const turma = db.classes.find((c) => c.id === user.classId) || null;
  res.render("student/index", { user, turma });
});

app.get("/aluno/desempenho", requireAuth, requireRole("student"), (req, res) => {
  const db = getDb();
  const user = req.currentUser;
  const activities = db.activities
    .filter((a) => a.classId === user.classId)
    .sort((a, b) => String(a.date).localeCompare(String(b.date)));
  const completionByActivityId = new Map(
    db.completions.filter((c) => c.studentId === user.id).map((c) => [c.activityId, c.done])
  );
  const rows = activities.map((a) => ({
    activity: a,
    done: completionByActivityId.has(a.id) ? completionByActivityId.get(a.id) : null
  }));
  res.render("student/performance", { rows });
});

app.get("/aluno/advertencias", requireAuth, requireRole("student"), (req, res) => {
  const db = getDb();
  const user = req.currentUser;
  const all = db.warnings
    .filter((w) => w.studentId === user.id)
    .sort((a, b) => String(b.date).localeCompare(String(a.date)));
  const pending = all.filter((w) => w.status === "pending");
  const resolved = all.filter((w) => w.status === "resolved");
  res.render("student/warnings", { pending, resolved });
});

app.get("/aluno/documentos", requireAuth, requireRole("student"), (req, res) => {
  const db = getDb();
  const user = req.currentUser;
  const docs = db.documents
    .filter((d) => d.visibility === "all" || d.classId === user.classId)
    .sort((a, b) => String(b.uploadedAt).localeCompare(String(a.uploadedAt)));
  res.render("student/documents", { docs });
});

app.get("/aluno/informacoes", requireAuth, requireRole("student"), (req, res) => {
  const db = getDb();
  const user = req.currentUser;
  const infos = db.infos
    .filter((i) => !i.classId || i.classId === user.classId)
    .sort((a, b) => String(a.date).localeCompare(String(b.date)));
  res.render("student/info", { infos });
});

app.get("/professor", requireAuth, requireRole("teacher"), (req, res) => {
  res.render("teacher/index");
});

app.get("/professor/turmas", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  res.render("teacher/classes", { classes, message: null });
});

app.post("/professor/turmas", requireAuth, requireRole("teacher"), (req, res) => {
  const code = normalizeNameToken(req.body.code);
  const name = String(req.body.name || code).trim() || code;
  if (!code) return res.status(400).send("Código inválido.");
  writeDb((db) => {
    if (db.classes.some((c) => c.code === code)) return;
    db.classes.push({ id: makeId("cls"), code, name, createdAt: isoNow() });
  });
  res.redirect("/professor/turmas");
});

app.get("/professor/alunos", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const students = db.users
    .filter((u) => u.role === "student")
    .map((u) => ({
      ...u,
      turma: db.classes.find((c) => c.id === u.classId) || null
    }))
    .sort((a, b) => String(a.fullName).localeCompare(String(b.fullName)));
  res.render("teacher/students", { classes, students, createdCredentials: null, error: null });
});

app.post("/professor/alunos", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const fullName = String(req.body.fullName || "").trim();
  const classId = String(req.body.classId || "").trim();
  const turma = db.classes.find((c) => c.id === classId) || null;
  if (!fullName || !turma) {
    const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
    const students = db.users.filter((u) => u.role === "student");
    return res.status(400).render("teacher/students", {
      classes,
      students,
      createdCredentials: null,
      error: "Informe nome completo e turma."
    });
  }
  const login = buildStudentLogin({ classCode: turma.code, fullName });
  const passwordPlain = generateStudentPassword();
  const firstName = normalizeNameToken(fullName.split(/\s+/)[0] || "");
  writeDb((db2) => {
    if (db2.users.some((u) => u.login === login)) return;
    db2.users.push({
      id: makeId("usr"),
      role: "student",
      login,
      passwordHash: hashPassword(passwordPlain),
      fullName,
      firstName,
      classId: turma.id,
      createdAt: isoNow()
    });
  });

  const db3 = getDb();
  const classes = [...db3.classes].sort((a, b) => a.code.localeCompare(b.code));
  const students = db3.users
    .filter((u) => u.role === "student")
    .map((u) => ({ ...u, turma: db3.classes.find((c) => c.id === u.classId) || null }))
    .sort((a, b) => String(a.fullName).localeCompare(String(b.fullName)));
  res.render("teacher/students", {
    classes,
    students,
    createdCredentials: { fullName, login, password: passwordPlain },
    error: null
  });
});

app.get("/professor/atividades", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const activities = db.activities
    .map((a) => ({ ...a, turma: db.classes.find((c) => c.id === a.classId) || null }))
    .sort((a, b) => `${a.turma?.code || ""}_${a.date}`.localeCompare(`${b.turma?.code || ""}_${b.date}`));
  res.render("teacher/activities", { classes, activities });
});

app.post("/professor/atividades", requireAuth, requireRole("teacher"), (req, res) => {
  const classId = String(req.body.classId || "").trim();
  const date = String(req.body.date || "").trim();
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  if (!classId || !date || !title) return res.status(400).send("Informe turma, data e título.");
  writeDb((db) => {
    db.activities.push({
      id: makeId("act"),
      classId,
      date,
      title,
      description,
      createdAt: isoNow()
    });
  });
  res.redirect("/professor/atividades");
});

app.get("/professor/lancamentos", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const classId = String(req.query.classId || "");
  const turma = classId ? db.classes.find((c) => c.id === classId) : null;
  const activities = turma
    ? db.activities.filter((a) => a.classId === turma.id).sort((a, b) => a.date.localeCompare(b.date))
    : [];
  const activityId = String(req.query.activityId || "");
  const activity = activityId ? activities.find((a) => a.id === activityId) : null;
  const students = turma
    ? db.users
        .filter((u) => u.role === "student" && u.classId === turma.id)
        .sort((a, b) => String(a.fullName).localeCompare(String(b.fullName)))
    : [];
  const completionByStudentId = new Map(
    db.completions.filter((c) => c.activityId === activityId).map((c) => [c.studentId, c.done])
  );
  res.render("teacher/activity_mark", { classes, turma, activities, activity, students, completionByStudentId });
});

app.post("/professor/lancamentos", requireAuth, requireRole("teacher"), (req, res) => {
  const activityId = String(req.body.activityId || "").trim();
  if (!activityId) return res.status(400).send("Atividade inválida.");
  writeDb((db) => {
    const activity = db.activities.find((a) => a.id === activityId);
    if (!activity) return;
    const students = db.users.filter((u) => u.role === "student" && u.classId === activity.classId);
    for (const student of students) {
      const done = safeInt(req.body[`done_${student.id}`]);
      const existing = db.completions.find((c) => c.activityId === activityId && c.studentId === student.id);
      if (existing) {
        existing.done = done ? 1 : 0;
        existing.updatedAt = isoNow();
      } else {
        db.completions.push({
          id: makeId("cmp"),
          activityId,
          studentId: student.id,
          done: done ? 1 : 0,
          createdAt: isoNow()
        });
      }
    }
  });
  res.redirect(`/professor/lancamentos?activityId=${encodeURIComponent(activityId)}`);
});

app.get("/professor/advertencias", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const students = db.users
    .filter((u) => u.role === "student")
    .map((u) => ({ ...u, turma: db.classes.find((c) => c.id === u.classId) || null }))
    .sort((a, b) => String(a.fullName).localeCompare(String(b.fullName)));
  res.render("teacher/warnings", { classes, students, message: null });
});

app.post("/professor/advertencias", requireAuth, requireRole("teacher"), (req, res) => {
  const studentId = String(req.body.studentId || "").trim();
  const date = String(req.body.date || "").trim() || new Date().toISOString().slice(0, 10);
  const type = String(req.body.type || "").trim();
  const observation = String(req.body.observation || "").trim();
  if (!studentId || !type) return res.status(400).send("Informe aluno e tipo.");
  writeDb((db) => {
    db.warnings.push({
      id: makeId("wrn"),
      studentId,
      date,
      type,
      status: "pending",
      createdAt: isoNow()
    });
    if (observation) {
      db.observations.push({
        id: makeId("obs"),
        studentId,
        date,
        text: observation,
        createdAt: isoNow()
      });
    }
  });
  res.redirect("/professor/advertencias");
});

app.get("/professor/documentos", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const documents = [...db.documents].sort((a, b) => String(b.uploadedAt).localeCompare(String(a.uploadedAt)));
  res.render("teacher/documents", { classes, documents, error: null });
});

app.post("/professor/documentos", requireAuth, requireRole("teacher"), upload.single("pdf"), (req, res) => {
  const title = String(req.body.title || "").trim();
  const visibility = String(req.body.visibility || "all");
  const classId = String(req.body.classId || "").trim();
  if (!title || !req.file) return res.status(400).send("Informe título e PDF.");
  writeDb((db) => {
    db.documents.push({
      id: makeId("doc"),
      title,
      visibility: visibility === "class" ? "class" : "all",
      classId: visibility === "class" ? classId : null,
      fileName: req.file.filename,
      originalName: req.file.originalname,
      uploadedAt: isoNow(),
      uploadedBy: req.currentUser.id
    });
  });
  res.redirect("/professor/documentos");
});

app.post("/professor/documentos/:id/remover", requireAuth, requireRole("teacher"), (req, res) => {
  const id = String(req.params.id);
  writeDb((db) => {
    const idx = db.documents.findIndex((d) => d.id === id);
    if (idx < 0) return;
    const [doc] = db.documents.splice(idx, 1);
    const filePath = path.join(uploadsDir, doc.fileName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });
  res.redirect("/professor/documentos");
});

app.get("/professor/informacoes", requireAuth, requireRole("teacher"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  const infos = [...db.infos].sort((a, b) => String(a.date).localeCompare(String(b.date)));
  res.render("teacher/info", { classes, infos });
});

app.post("/professor/informacoes", requireAuth, requireRole("teacher"), (req, res) => {
  const type = String(req.body.type || "lembrete").trim();
  const date = String(req.body.date || "").trim();
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  const scope = String(req.body.scope || "all");
  const classId = String(req.body.classId || "").trim();
  if (!date || !title) return res.status(400).send("Informe data e título.");
  writeDb((db) => {
    db.infos.push({
      id: makeId("inf"),
      type,
      date,
      title,
      body,
      classId: scope === "class" ? classId : null,
      createdAt: isoNow()
    });
  });
  res.redirect("/professor/informacoes");
});

app.get("/coordenacao", requireAuth, requireRole("coordinator"), (req, res) => {
  const db = getDb();
  const classes = [...db.classes].sort((a, b) => a.code.localeCompare(b.code));
  res.render("coordinator/index", { classes });
});

function pendingWarningsCount(db, studentId) {
  return db.warnings.filter((w) => w.studentId === studentId && w.status === "pending").length;
}

app.get("/coordenacao/turma/:classId", requireAuth, requireRole("coordinator"), (req, res) => {
  const db = getDb();
  const turma = db.classes.find((c) => c.id === req.params.classId);
  if (!turma) return res.status(404).send("Turma não encontrada.");
  const students = db.users
    .filter((u) => u.role === "student" && u.classId === turma.id)
    .sort((a, b) => String(a.fullName).localeCompare(String(b.fullName)))
    .map((s) => ({
      ...s,
      pendingWarnings: pendingWarningsCount(db, s.id)
    }));
  const activities = db.activities.filter((a) => a.classId === turma.id).sort((a, b) => a.date.localeCompare(b.date));
  const completionByKey = new Map(db.completions.map((c) => [`${c.activityId}:${c.studentId}`, c.done]));
  res.render("coordinator/class", { turma, students, activities, completionByKey });
});

app.get("/coordenacao/aluno/:studentId", requireAuth, requireRole("coordinator"), (req, res) => {
  const db = getDb();
  const student = db.users.find((u) => u.id === req.params.studentId && u.role === "student");
  if (!student) return res.status(404).send("Aluno não encontrado.");
  const turma = db.classes.find((c) => c.id === student.classId) || null;
  const warnings = db.warnings
    .filter((w) => w.studentId === student.id)
    .sort((a, b) => String(b.date).localeCompare(String(a.date)));
  const pending = warnings.filter((w) => w.status === "pending");
  const resolved = warnings.filter((w) => w.status === "resolved");
  const observations = db.observations
    .filter((o) => o.studentId === student.id)
    .sort((a, b) => String(b.date).localeCompare(String(a.date)));
  res.render("coordinator/student", { student, turma, pending, resolved, observations });
});

app.post("/coordenacao/aluno/:studentId/resolver", requireAuth, requireRole("coordinator"), (req, res) => {
  const studentId = String(req.params.studentId);
  writeDb((db) => {
    for (const w of db.warnings) {
      if (w.studentId === studentId && w.status === "pending") {
        w.status = "resolved";
        w.resolvedAt = isoNow();
      }
    }
  });
  res.redirect(`/coordenacao/aluno/${encodeURIComponent(studentId)}`);
});

app.listen(port, () => {
  console.log(`Meu horizonte rodando em http://localhost:${port}`);
});
