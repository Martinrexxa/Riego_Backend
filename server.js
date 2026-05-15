require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const cors = require("cors");
const crypto = require("crypto");
const https = require("https");

// ─── Tuya Cloud API ──────────────────────────────────────────────────────────
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = process.env.TUYA_DEVICE_ID;
const TUYA_HOSTNAME      = "openapi.tuyaus.com";

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

function hmacUpper(str, secret) {
  return crypto.createHmac("sha256", secret).update(str, "utf8").digest("hex").toUpperCase();
}

function tuyaRequest(apiPath, method, body, token) {
  return new Promise((resolve, reject) => {
    const t       = Date.now().toString();
    const nonce   = "";
    const bodyStr = body ? JSON.stringify(body) : "";
    const contentHash  = sha256Hex(bodyStr);
    const stringToSign = `${method}\n${contentHash}\n\n${apiPath}`;
    const signInput    = token
      ? `${TUYA_CLIENT_ID}${token}${t}${nonce}${stringToSign}`
      : `${TUYA_CLIENT_ID}${t}${nonce}${stringToSign}`;
    const sign = hmacUpper(signInput, TUYA_CLIENT_SECRET);

    const headers = {
      "client_id":   TUYA_CLIENT_ID,
      "t":           t,
      "sign":        sign,
      "sign_method": "HMAC-SHA256",
      "nonce":       nonce,
      "Content-Type": "application/json",
    };
    if (token) headers["access_token"] = token;
    if (bodyStr) headers["Content-Length"] = Buffer.byteLength(bodyStr).toString();

    const req = https.request(
      { hostname: TUYA_HOSTNAME, path: apiPath, method, headers },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try { resolve(JSON.parse(raw)); }
          catch { reject(new Error("Tuya respuesta no-JSON: " + raw)); }
        });
      }
    );
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function tuyaGetToken() {
  const data = await tuyaRequest("/v1.0/token?grant_type=1", "GET", null, null);
  if (!data.success) throw new Error("Tuya token error: " + (data.msg || JSON.stringify(data)));
  return data.result.access_token;
}

async function tuyaControlValve(open) {
  const token = await tuyaGetToken();
  const path  = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
  const code = "switch_1";
  const result = await tuyaRequest(
    path,
    "POST",
    { commands: [{ code, value: open }] },
    token
  );

  if (result.success) {
    return { success: true, codeUsed: code, raw: result };
  }

  return {
    success: false,
    message: "Tuya no acepto el comando switch_1",
    lastError: { code, result },
  };
}

async function tuyaGetValveStatus() {
  const token = await tuyaGetToken();
  const path  = `/v1.0/devices/${TUYA_DEVICE_ID}/status`;
  return tuyaRequest(path, "GET", null, token);
}

const valveTransition = {
  inProgress: false,
  targetOpen: null,
  action: null,
  startedAt: null,
  lastCommandAt: null
};
const VALVE_TRANSITION_MIN_MS = 17000;
// ─────────────────────────────────────────────────────────────────────────────

const app = express();

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
//app.use(express.static(path.join(__dirname, '../frontend/Sis_rie/Public')));



console.log("DATABASE_URL:", process.env.DATABASE_URL);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
   ssl: {
    rejectUnauthorized: false
  }
});
pool.on("error", (err) => {
  console.error("Error inesperado en pool de PostgreSQL:", err.message);
});
console.log("Pool PostgreSQL inicializado");
// ======================
//        HTML
// ======================


// ======================
//        LOGIN
// ======================
app.post("/api/login", async (req, res) => {
  console.log("BODY:", req.body);
  const { usuario, contrasena } = req.body;

  if (!usuario || !contrasena) {
    return res.json({ success: false, message: "Faltan datos de login" });
  }

  try {
    const result = await pool.query(`
     SELECT 
  u.usuario,
  u.correo,
  u.estado,
  r.nombre AS rolnombre,
  e.nombre AS empleadonombre,
  e.apellido AS empleadoapellido,
  u.contrasena_hash
     FROM usuarios u
LEFT JOIN roles r ON u.rol_id = r.rol_id
LEFT JOIN empleados e ON u.empleado_id = e.id_empleado
WHERE u.usuario = $1
    `, [usuario]);

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Usuario no encontrado" });
    }

   const user = result.rows[0];

if (!user.estado) {
  return res.json({ success: false, message: "Usuario inactivo" });
}

const match = await bcrypt.compare(contrasena, user.contrasena_hash);

    if (!match) {
      return res.json({ success: false, message: "Contraseña incorrecta" });
    }

    return res.json({
  success: true,
  redirect: "/dashboard",
  user: {
    nombreCompleto: `${user.empleadonombre} ${user.empleadoapellido}`,
    rol: user.rolnombre,
    correo: user.correo,
    usuario: user.usuario
  }
});

  } catch (err) {
    console.log("Error:", err);
    return res.status(500).json({ success: false, message: "Error en servidor" });
  }
});

// ======================
//      CREAR USUARIO
// ======================
app.post("/api/usuarios/create", async (req, res) => {
  const { nombre, correo, usuario, contrasena, rolID, empleadoID } = req.body;

  if (!nombre || !correo || !usuario || !contrasena || !rolID || !empleadoID) {
    return res.json({ success: false, message: "Faltan datos obligatorios" });
  }

  try {
    const hash = await bcrypt.hash(contrasena, 10);

    await pool.query(
      `
      INSERT INTO "Usuarios"
      ("Nombre","Correo","Usuario","ContrasenaHash","Estado","FechaRegistro","RolID","EmpleadoID")
      VALUES ($1,$2,$3,$4,true,NOW(),$5,$6)
      `,
      [nombre, correo, usuario, hash, rolID, empleadoID]
    );

    return res.json({ success: true, message: "Usuario creado correctamente" });

  } catch (err) {
    console.log("Error al crear usuario:", err);
    return res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.post("/api/riego", async (req, res) => {
  try {
    const { estado } = req.body; // "ON" | "OFF"
    const open = estado === "ON";
    const now = Date.now();

    valveTransition.inProgress = true;
    valveTransition.targetOpen = open;
    valveTransition.action = open ? "opening" : "closing";
    valveTransition.startedAt = now;
    valveTransition.lastCommandAt = now;

    console.log("Riego Tuya:", estado);
    const result = await tuyaControlValve(open);
    console.log("Tuya respuesta:", JSON.stringify(result));

    if (result.success) {
      return res.json({
        success: true,
        codeUsed: result.codeUsed,
        transition: valveTransition,
        message: `Válvula ${open ? "abierta" : "cerrada"} correctamente`
      });
    } else {
      valveTransition.inProgress = false;
      return res.status(502).json({
        success: false,
        message: `Tuya error: ${result.lastError?.result?.msg || result.message || JSON.stringify(result)}`
      });
    }
  } catch (error) {
    console.log("Error en riego:", error);
    return res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.get("/api/valvula/estado", async (req, res) => {
  try {
    const result = await tuyaGetValveStatus();
    console.log("Tuya estado válvula:", JSON.stringify(result));

    if (!result.success) {
      return res.status(502).json({
        success: false,
        message: `Tuya error: ${result.msg || JSON.stringify(result)}`
      });
    }

    const switchDp =
      result.result.find((dp) => ["switch", "switch_1", "valve_switch", "start"].includes(dp.code)) ||
      result.result.find((dp) => typeof dp.value === "boolean");
    const abierta  = switchDp ? switchDp.value : null;

    const elapsed = valveTransition.startedAt ? Date.now() - valveTransition.startedAt : 0;
    const minTransitionReached = elapsed >= VALVE_TRANSITION_MIN_MS;

    if (
      valveTransition.inProgress &&
      abierta !== null &&
      abierta === valveTransition.targetOpen &&
      minTransitionReached
    ) {
      valveTransition.inProgress = false;
      valveTransition.action = null;
      valveTransition.startedAt = null;
    }

    return res.json({
      success: true,
      abierta,
      dpCode: switchDp?.code || null,
      transition: valveTransition
    });
  } catch (error) {
    console.log("Error estado valvula:", error);
    return res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});
// ======================
//      ROLES
// ======================
// ======================
app.get("/api/roles", async (req, res) => {
  try {
   const result = await pool.query(`
  SELECT rol_id, nombre FROM roles
`);
    res.json({ success: true, roles: result.rows });

  } catch (err) {
    res.status(500).json({ success: false, message: "Error cargando roles" });
  }
});

// ======================
//     EMPLEADOS
// ======================
app.get("/api/empleados", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT "ID_empleado","Nombre","Apellido" FROM "Empleados"`
    );
    res.json({ success: true, empleados: result.rows });

  } catch (err) {
    res.status(500).json({ success: false, message: "Error cargando empleados" });
  }
});

process.on("uncaughtException", (err) => {
  console.error("❌ CRASH uncaughtException:", err.message);
  console.error(err.stack);
});
process.on("unhandledRejection", (reason) => {
  console.error("❌ CRASH unhandledRejection:", reason);
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`🔥 Servidor corriendo en puerto ${PORT}`);
});
server.on("error", (err) => {
  console.error("❌ Error al iniciar servidor:", err.message);
});
server.ref();








