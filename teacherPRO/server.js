const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcrypt");
const path = require("path");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

const app = express();
const port = 3000;

// Настройка базы данных SQLiteF
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
          args: [6, 100],
          msg: "Пароль должен быть от 6 до 100 символов",
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

// Модель Development
const Development = sequelize.define(
  "Development",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "development_id",
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    file_path: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    preview: {
      type: DataTypes.STRING,
    },
    categoryId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "category_id",
      references: {
        model: "categories",
        key: "id",
      },
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
  }
);

// Модель Category
const Category = sequelize.define(
  "Category",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "category_id",
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    timestamps: false,
    tableName: "categories",
  }
);

// Модель Tag
const Tag = sequelize.define(
  "Tag",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "tag_id",
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    timestamps: false,
    tableName: "tags",
  }
);
// Модель DownloadHistory
const DownloadHistory = sequelize.define(
  "DownloadHistory",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "download_history_id",
    },
    download_date: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.NOW,
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
    developmentId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "development_id",
      references: {
        model: "developments",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
    tableName: "download_history",
  }
);

// Модель Profile
const Profile = sequelize.define(
  "Profile",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "profile_id",
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
    tableName: "profiles",
  }
);

// Связующая таблица DevelopmentTags для Many-to-Many
const DevelopmentTags = sequelize.define(
  "DevelopmentTags",
  {},
  { timestamps: false, tableName: "development_tags" }
);

// Определение связей

Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: "roleId" });

User.hasMany(Development, { foreignKey: "userId", as: "developments" });
Development.belongsTo(User, { foreignKey: "userId", as: "user" });

User.hasMany(DownloadHistory, { foreignKey: "userId", as: "downloads" });
DownloadHistory.belongsTo(User, { foreignKey: "userId", as: "user" });

Category.hasMany(Development, { foreignKey: "categoryId", as: "developments" });
Development.belongsTo(Category, { foreignKey: "categoryId", as: "category" });

// Many-to-Many между Development и Tag
Development.belongsToMany(Tag, {
  through: DevelopmentTags,
  foreignKey: "developmentId",
  as: "tags",
});
Tag.belongsToMany(Development, {
  through: DevelopmentTags,
  foreignKey: "tagId",
  as: "developments",
});

// Profile
User.hasOne(Profile, { foreignKey: "userId", as: "profile" });
Profile.belongsTo(User, { foreignKey: "userId", as: "user" });

// DownloadHistory
Profile.hasMany(DownloadHistory, {
  foreignKey: "userId",
  as: "downloadHistory",
});
DownloadHistory.belongsTo(Profile, { foreignKey: "userId", as: "profile" });
Development.hasMany(DownloadHistory, {
  foreignKey: "developmentId",
  as: "downloads",
});
DownloadHistory.belongsTo(Development, {
  foreignKey: "developmentId",
  as: "development",
});

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
app.use(express.json()); // Middleware для обработки JSON
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: "secret-key",
    resave: true,
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
  res.render("index", { user: req.session.user });
});

// Роут для страницы каталога
app.get("/catalog", async (req, res) => {
  res.render("catalog", { user: req.session.user });
});

// Роут для страницы о нас
app.get("/about_us", async (req, res) => {
  res.render("about_us", { user: req.session.user });
});

// Роут для страницы регистрации
app.get("/register", async (req, res) => {
  res.render("register", { user: req.session.user, error: null });
});

// Роут для страницы добавления разработки
app.get("/addDevelopment", isAuthenticated, async (req, res) => {
  res.render("addDevelopment", { user: req.session.user, error: null });
});

// Роут для страницы подробнее для разработки
app.get("/card", isAuthenticated, async (req, res) => {
  res.render("card", { user: req.session.user, error: null });
});

// Роут для получения разработок пользователя
app.get("/user/developments/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;

  try {
    const developments = await Development.findAll({
      where: { userId },
    });
    res.json(developments);
  } catch (error) {
    console.error("Ошибка при получении разработок пользователя:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для получения истории скачиваний пользователя
app.get("/user/downloads/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;

  try {
    const downloads = await DownloadHistory.findAll({
      where: { userId },
      include: [{ model: Development, as: "development" }],
    });
    res.json(downloads);
  } catch (error) {
    console.error("Ошибка при получении истории скачиваний:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Админ панель
app.get("/admin", isAuthenticated, hasRole("admin"), async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ["id", "fullName", "email"],
      order: [["fullName", "ASC"]],
      where: {
        "$Role.name$": {
          [Sequelize.Op.not]: "admin",
        },
      },
      include: [
        {
          model: Role,
          required: true,
          attributes: [],
        },
      ],
    });
    const userCount = users.length;
    res.render("admin", { user: req.session.user, users, userCount });
  } catch (error) {
    console.error("Ошибка получения списка пользователей:", error);
    res.status(500).send("Ошибка сервера");
  }
});
// Настройка multer для обработки загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "public", "uploads"));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|pdf|docx|pptx|mp4/;
  if (!allowedTypes.test(file.mimetype)) {
    return cb("Ошибка: Неправильный тип файла.", false);
  }
  if (file.size > 10 * 1024 * 1024) {
    return cb("Ошибка: Файл слишком большой. Максимальный размер - 10 МБ.");
  }
  cb(null, true);
};

const uploads = multer({ storage: storage, fileFilter: fileFilter });

// AJAX endpoints для добавления
app.post(
  "/admin/add/tag",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === "") {
      return res.status(400).send({ error: "Имя тега не может быть пустым." });
    }
    try {
      const existingTag = await Tag.findOne({ where: { name: name.trim() } });
      if (existingTag) {
        return res
          .status(400)
          .send({ error: "Тег с таким именем уже существует." });
      }
      const tag = await Tag.create({ name: name.trim() });
      res.status(201).send({ success: true, tag });
    } catch (error) {
      console.error("Ошибка при добавлении тега:", error);
      res.status(500).send({ error: "Ошибка сервера." });
    }
  }
);
app.post(
  "/admin/add/category",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === "") {
      return res
        .status(400)
        .send({ error: "Имя категории не может быть пустым." });
    }
    try {
      const existingCategory = await Category.findOne({
        where: { name: name.trim() },
      });
      if (existingCategory) {
        return res
          .status(400)
          .send({ error: "Категория с таким именем уже существует." });
      }
      const category = await Category.create({ name: name.trim() });
      res.status(201).send({ success: true, category });
    } catch (error) {
      console.error("Ошибка при добавлении категории:", error);
      res.status(500).send({ error: "Ошибка сервера." });
    }
  }
);
app.post(
  "/admin/add/development",
  isAuthenticated,
  hasRole("admin"),
  uploads.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { title, description, categoryId, tags } = req.body;
      const userId = req.session.user.id;
      if (!req.files || !req.files["preview"] || !req.files["file_path"]) {
        return res.status(400).send({ error: "Не загружены файлы." });
      }

      const previewPath = req.files["preview"][0].path.replace("public\\", "");
      const filePath = req.files["file_path"][0].path.replace("public\\", "");

      const development = await Development.create({
        title,
        description,
        file_path: filePath,
        preview: previewPath,
        categoryId,
        userId,
      });

      if (tags && tags.length > 0) {
        const tagIds = Array.isArray(tags) ? tags : tags.split(",").map(Number);
        await development.setTags(tagIds);
      }

      res.status(201).send({ success: true, development });
    } catch (error) {
      console.error("Ошибка при добавлении разработки:", error);
      if (error instanceof multer.MulterError) {
        return res.status(400).send({ error: error.message });
      }
      res.status(500).send({ error: "Ошибка при добавлении разработки" });
    }
  }
);

app.get(
  "/admin/categories",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const categories = await Category.findAll();
      res.status(200).json(categories);
    } catch (error) {
      console.error("Ошибка получения категорий:", error);
      res.status(500).send("Ошибка сервера");
    }
  }
);

app.get("/admin/tags", isAuthenticated, hasRole("admin"), async (req, res) => {
  try {
    const tags = await Tag.findAll();
    res.status(200).json(tags);
  } catch (error) {
    console.error("Ошибка получения тегов:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для обработки регистрации
app.post("/register", async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("register", {
      user: req.session.user,
      error: "Пароли не совпадают",
    });
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
    res.render("register", { user: req.session.user, error: message });
  }
});

// Роут для страницы авторизации
app.get("/login", (req, res) => {
  res.render("login", { user: req.session.user, error: null });
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
      res.render("login", {
        user: req.session.user,
        error: "Неверный email или пароль",
      });
    }
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.render("login", { user: req.session.user, error: "Ошибка входа" });
  }
});

// Роут для страницы профиля
app.get("/profile", isAuthenticated, (req, res) => {
  res.render("profile", { user: req.session.user });
});

// Роут для страницы профиля
app.get("/profile", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    let profile = await Profile.findOne({ where: { userId } });
    if (!profile) {
      profile = await Profile.create({ userId });
    }

    const user = await User.findByPk(userId, {
      include: [
        {
          model: Development,
          as: "developments",
          attributes: ["title", "description", "id"],
        },
        {
          model: DownloadHistory,
          as: "downloadHistory",
          attributes: ["developmentId", "download_date"],
          include: {
            model: Development,
            attributes: ["title"],
          },
        },
      ],
    });
    if (!user) {
      return res.status(404).send("Пользователь не найден");
    }
    res.render("profile", {
      user: req.session.user,
      profile: user.profile,
      developments: user.developments,
      downloads: user.downloadHistory,
    });
  } catch (error) {
    console.error("Ошибка получения профиля:", error);
    res.status(500).send("Ошибка сервера");
  }
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
