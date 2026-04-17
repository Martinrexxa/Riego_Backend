require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const cors = require("cors");

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
pool.connect()
  .then(() => console.log("✅ Conectado a Neon"))
  .catch(err => console.log("❌ Error conectando a Neon:", err));
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

// ======================
//      ROLES
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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🔥 Servidor corriendo en puerto ${PORT}`);
});