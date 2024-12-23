const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const port = 3000;

// Настройка базы данных SQLite
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "db.sqlite",
});

// Модель роли
const Role = sequelize.define(
  "Role",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  { timestamps: false }
);

// Модель пользователей
const User = sequelize.define(
  "User",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    fullName: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: { msg: "ФИО не может быть пустым" },
        len: {
          args: [3, 100],
          msg: "ФИО должно быть от 3 до 100 символов",
        },
      },
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: { msg: "Некорректный формат email" },
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [0, 100],
          msg: "Пароль должен быть от 6 до 50 символов",
        },
      },
    },
    roleId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: Role,
        key: "id",
      },
    },
  },
  { timestamps: false }
);

// Установка связей
Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: "roleId" });

// Синхронизация базы данных и создание админа при первом запуске
sequelize
  .sync({ force: false })
  .then(async () => {
    console.log("База данных синхронизирована");

    // Создаем роли если их еще нет
    const userRole = await Role.findOrCreate({
      where: { name: "user" },
      defaults: { name: "user" },
    });
    const adminRole = await Role.findOrCreate({
      where: { name: "admin" },
      defaults: { name: "admin" },
    });

    //Проверка есть ли пользователи в бд
    const usersCount = await User.count();

    // Если нет пользователей - создаем админа
    if (usersCount === 0) {
      const hashedPassword = await bcrypt.hash("admin", 10);
      await User.create({
        fullName: "Admin",
        email: "admin@example.com",
        password: hashedPassword,
        roleId: adminRole[0].id,
      });
      console.log("Администратор создан");
    }
  })
  .catch((err) => console.error(err));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Проверка авторизации
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Проверка роли
function hasRole(roleName) {
  return async (req, res, next) => {
    if (req.session.user) {
      const user = await User.findByPk(req.session.user.id, { include: Role });
      if (user && user.Role.name === roleName) {
        next();
      } else {
        res.status(403).send("Доступ запрещен");
      }
    } else {
      res.redirect("/login");
    }
  };
}

// Маршруты

// Главная страница
app.get("/", (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === "admin") {
      res.redirect("/admin");
    } else {
      res.redirect("/profile");
    }
  } else {
    res.redirect("/index");
  }
});

// Роут для главной страницы
app.get("/index", async (req, res) => {
  res.render("index", { error: null });
});

// Роут для страницы каталога
app.get("/catalog", async (req, res) => {
  res.render("catalog", { error: null });
});

// Роут для страницы о нас
app.get("/about_us", async (req, res) => {
  res.render("about_us", { error: null });
});

// Роут для страницы карточки товара
app.get("/card", async (req, res) => {
  res.render("card", { error: null });
});

// Роут для страницы загрузки разработок
app.get("/new", async (req, res) => {
  res.render("new", { error: null });
});

// Роут для страницы регистрации
app.get("/register", async (req, res) => {
  res.render("register", { error: null });
});

// Роут для обработки регистрации
app.post("/register", async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("register", { error: "Пароли не совпадают" });
  }
  try {
    const role = await Role.findOne({ where: { name: "user" } });
    if (!role) {
      return res.status(400).send("Роль не найдена");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      fullName,
      email,
      password: hashedPassword,
      roleId: role.id,
    });
    res.redirect("/login");
  } catch (error) {
    let message = "Ошибка регистрации";
    if (error.name === "SequelizeUniqueConstraintError") {
      message = "Пользователь с таким email уже существует";
    } else if (error.errors) {
      message = error.errors.map((err) => err.message).join(", ");
    }
    console.error("Ошибка регистрации:", error);
    res.render("register", { error: message });
  }
});

// Роут для страницы авторизации
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// Роут для обработки авторизации
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email }, include: Role });
    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.Role.name,
        fullName: user.fullName,
      };

      if (user.Role.name === "admin") {
        res.redirect("/admin");
      } else {
        res.redirect("/profile");
      }
    } else {
      res.render("login", { error: "Неверный email или пароль" });
    }
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.render("login", { error: "Ошибка входа" });
  }
});

// Роут для страницы профиля
app.get("/profile", isAuthenticated, (req, res) => {
  res.render("profile", { user: req.session.user });
});

// Роут для страницы админа
app.get("/admin", isAuthenticated, hasRole("admin"), (req, res) => {
  res.render("admin", { user: req.session.user });
});

// Роут для выхода
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Ошибка при выходе:", err);
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту http://localhost:${port}`);
});
