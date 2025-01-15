const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcrypt");
const multer = require("multer");
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
  {
    developmentId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "development_id",
      references: {
        model: "developments",
        key: "development_id",
      },
    },
    tagId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "tag_id",
      references: {
        model: "tags",
        key: "tag_id",
      },
    },
  },
  { timestamps: false, tableName: "development_tags" }
);

// Определение связей

Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: "roleId" });

User.hasMany(Development, { foreignKey: "userId", as: "developments" });
Development.belongsTo(User, { foreignKey: "userId", as: "user" });

User.hasMany(DownloadHistory, { foreignKey: "userId", as: "downloads" });
DownloadHistory.belongsTo(User, { foreignKey: "userId", as: "user" });

Category.hasMany(Development, {
  foreignKey: "categoryId",
  as: "developments",
});
Development.belongsTo(Category, {
  foreignKey: "categoryId",
  as: "category",
});
// Many-to-Many между Development и Tag
Development.belongsToMany(Tag, {
  through: DevelopmentTags,
  foreignKey: "development_id",
  as: "tags",
});
Tag.belongsToMany(Development, {
  through: DevelopmentTags,
  foreignKey: "tag_id",
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
  foreignKey: "development_id",
  as: "downloads",
});
DownloadHistory.belongsTo(Development, {
  foreignKey: "development_id",
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
  try {
    const developments = await Development.findAll({
      include: [
        { model: Category, as: "category" },
        { model: Tag, through: DevelopmentTags, as: "tags" },
      ],
    });
    const categories = await Category.findAll();
    const tags = await Tag.findAll();
    res.render("catalog", {
      user: req.session.user,
      developments,
      categories,
      tags,
    });
  } catch (error) {
    console.error("Ошибка получения каталога:", error);
    res.status(500).send("Ошибка сервера");
  }
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
    const categories = await Category.findAll();
    const tags = await Tag.findAll();
    res.render("admin", {
      user: req.session.user,
      users,
      userCount,
      categories,
      tags,
    });
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
  const allowedMimeTypes = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "video/mp4",
  ];

  const allowedExtensions = [
    ".jpeg",
    ".jpg",
    ".png",
    ".pdf",
    ".docx",
    ".ppt",
    ".pptx",
    ".mp4",
  ];

  const mimeType = file.mimetype.toLowerCase();
  const extension = path.extname(file.originalname).toLowerCase();

  if (
    !allowedMimeTypes.includes(mimeType) ||
    !allowedExtensions.includes(extension)
  ) {
    return cb("Ошибка: Неправильный тип файла.", false);
  }

  if (file.size > 10 * 1024 * 1024) {
    return cb("Ошибка: Файл слишком большой. Максимальный размер - 10 МБ.");
  }

  cb(null, true);
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 },
});
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

// Функция для создания URL-адреса step2 в зависимости от роли
function getAddDevelopmentStep2Route(req, developmentId) {
  return req.session.user.role === "admin"
    ? `/admin/add/development/step2/${developmentId}`
    : `/user/add/development/step2/${developmentId}`;
}

app.post(
  "/admin/add/development/step1",
  isAuthenticated,
  hasRole("admin"),
  upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { title, description, category_id } = req.body;
      const userId = req.session.user.id;

      if (!req.files || !req.files["preview"] || !req.files["file_path"]) {
        return res.status(400).json({ error: "Не загружены файлы." });
      }

      const previewFile = req.files["preview"][0];
      const filePathFile = req.files["file_path"][0];

      const previewPath = path
        .join("uploads", path.basename(previewFile.path))
        .replace(/\\/g, "/");
      const filePath = path
        .join("uploads", path.basename(filePathFile.path))
        .replace(/\\/g, "/");

      const parsedCategoryId = parseInt(category_id, 10);
      if (isNaN(parsedCategoryId)) {
        return res.status(400).json({ error: "Некорректный ID категории" });
      }
      const development = await Development.create({
        title,
        description,
        file_path: filePath,
        preview: previewPath,
        categoryId: parsedCategoryId,
        userId,
      });

      console.log("Путь к превью:", previewPath);
      console.log("Путь к файлу:", filePath);

      const tags = await Tag.findAll();
      res.json({
        success: true,
        developmentId: development.id,
        tagsHtml: renderTagsHtml(tags, development.id),
      });
    } catch (error) {
      console.error("Ошибка при добавлении разработки:", error);
      if (error instanceof multer.MulterError) {
        return res.status(400).json({ error: error.message });
      } else if (
        error.name === "SequelizeValidationError" ||
        error.name === "SequelizeUniqueConstraintError"
      ) {
        const errors = error.errors.map((err) => err.message);
        return res.status(400).json({ error: errors.join(", ") });
      }
      res.status(500).json({ error: "Ошибка при добавлении разработки" });
    }
  }
);

app.post(
  "/admin/add/development/step2/:developmentId",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const developmentId = parseInt(req.params.developmentId, 10);
      if (isNaN(developmentId)) {
        return res.status(400).json({ error: "Некорректный ID разработки" });
      }
      const { tags } = req.body;
      const development = await Development.findByPk(developmentId);
      if (!development) {
        return res.status(404).json({ error: "Разработка не найдена" });
      }

      let tagIds = [];
      if (tags) {
        tagIds = Array.isArray(tags)
          ? tags
          : tags.split(",").map(Number).filter(Boolean);
      }
      const developmentTags = await development.getTags();
      for (const tag of developmentTags) {
        await DevelopmentTags.destroy({
          where: { developmentId, tagId: tag.id },
        });
      }
      if (tagIds && tagIds.length > 0) {
        const toCreate = tagIds.map((tagId) => ({
          developmentId: development.id,
          tagId: tagId,
        }));
        await DevelopmentTags.bulkCreate(toCreate, {
          validate: true,
          individualHooks: true,
        });
      }

      res.json({ success: true, redirect: "/admin" });
    } catch (error) {
      console.error("Ошибка при добавлении тегов:", error);
      if (
        error.name === "SequelizeValidationError" ||
        error.name === "SequelizeUniqueConstraintError"
      ) {
        const errors = error.errors.map((err) => err.message);
        return res.status(400).json({ error: errors.join(", ") });
      }
      res.status(500).json({ error: "Ошибка сервера" });
    }
  }
);

// Этап 1: Создание разработки (без тегов) для пользователя
app.post(
  "/user/add/development/step1",
  isAuthenticated,
  upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { title, description, category_id } = req.body;
      const userId = req.session.user.id;

      if (!req.files || !req.files["preview"] || !req.files["file_path"]) {
        return res.status(400).json({ error: "Не загружены файлы." });
      }

      const previewFile = req.files["preview"][0];
      const filePathFile = req.files["file_path"][0];

      const previewPath = path
        .join("uploads", path.basename(previewFile.path))
        .replace(/\\/g, "/");
      const filePath = path
        .join("uploads", path.basename(filePathFile.path))
        .replace(/\\/g, "/");

      const parsedCategoryId = parseInt(category_id, 10);
      if (isNaN(parsedCategoryId)) {
        return res.status(400).json({ error: "Некорректный ID категории" });
      }
      const development = await Development.create({
        title,
        description,
        file_path: filePath,
        preview: previewPath,
        categoryId: parsedCategoryId,
        userId,
      });
      const tags = await Tag.findAll();
      res.json({
        success: true,
        developmentId: development.id,
        tagsHtml: renderTagsHtml(tags, development.id),
      });
    } catch (error) {
      console.error("Ошибка при добавлении разработки:", error);
      if (error instanceof multer.MulterError) {
        return res.status(400).json({ error: error.message });
      } else if (
        error.name === "SequelizeValidationError" ||
        error.name === "SequelizeUniqueConstraintError"
      ) {
        const errors = error.errors.map((err) => err.message);
        return res.status(400).json({ error: errors.join(", ") });
      }
      res.status(500).json({ error: "Ошибка при добавлении разработки" });
    }
  }
);

// Этап 2: Добавление тегов к разработке для пользователя
app.post(
  "/user/add/development/step2/:developmentId",
  isAuthenticated,
  async (req, res) => {
    try {
      const developmentId = parseInt(req.params.developmentId, 10);
      if (isNaN(developmentId)) {
        return res.status(400).json({ error: "Некорректный ID разработки" });
      }
      const { tags } = req.body;
      const development = await Development.findByPk(developmentId);
      if (!development) {
        return res.status(404).json({ error: "Разработка не найдена" });
      }

      let tagIds = [];
      if (tags) {
        tagIds = Array.isArray(tags)
          ? tags
          : tags.split(",").map(Number).filter(Boolean);
      }

      const developmentTags = await development.getTags();
      for (const tag of developmentTags) {
        await DevelopmentTags.destroy({
          where: { developmentId, tagId: tag.id },
        });
      }
      if (tagIds && tagIds.length > 0) {
        const toCreate = tagIds.map((tagId) => ({
          developmentId: development.id,
          tagId: tagId,
        }));
        await DevelopmentTags.bulkCreate(toCreate, {
          validate: true,
          individualHooks: true,
        });
      }
      res.json({ success: true, redirect: "/profile" });
    } catch (error) {
      console.error("Ошибка при добавлении тегов:", error);
      if (
        error.name === "SequelizeValidationError" ||
        error.name === "SequelizeUniqueConstraintError"
      ) {
        const errors = error.errors.map((err) => err.message);
        return res.status(400).json({ error: errors.join(", ") });
      }
      res.status(500).json({ error: "Ошибка сервера" });
    }
  }
);

// Функция для создания URL-адреса в зависимости от роли пользователя
function getAddDevelopmentRoute(req) {
  return req.session.user.role === "admin"
    ? "/admin/add/development"
    : "/user/addDevelopment";
}

// Функция для создания URL-адреса step2 в зависимости от роли
function getAddDevelopmentStep2Route(req, developmentId) {
  return req.session.user.role === "admin"
    ? `/admin/add/development/step2/${developmentId}`
    : `/user/add/development/step2/${developmentId}`;
}

// Роут для отображения страницы загрузки для пользователя
app.get("/user/addDevelopment", isAuthenticated, async (req, res) => {
  res.render("addDevelopment", { user: req.session.user });
});

function renderTagsHtml(tags, developments) {
  return `
       <h3>Выберите теги:</h3>
          <div id="tagList">
          ${tags
            .map(
              (tag) => `
                <input type="checkbox" name="tags" value="${tag.id}" id="tag${tag.id}">
                <label for="tag${tag.id}">${tag.name}</label><br>
             `
            )
            .join("")}
         </div>
         <button type="submit">Подтвердить загрузку</button>
    `;
}

app.post(
  "/admin/developments/delete/:id",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    const developmentId = req.params.id;
    try {
      await Development.destroy({ where: { id: developmentId } });
      res.redirect("/admin");
    } catch (error) {
      console.error("Ошибка удаления разработки:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);

app.get(
  "/admin/developments",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const developments = await Development.findAll({
        include: [
          { model: Category, as: "category" },
          { model: Tag, as: "tags", through: { attributes: [] } },
        ],
      });
      res.json(
        developments.map((development) => ({
          ...development.get(),
          category: development.category ? development.category.get() : null,
          tags: development.tags
            ? development.tags.map((tag) => tag.get())
            : [],
        }))
      );
    } catch (error) {
      console.error("Ошибка получения разработок:", error);
      res.status(500).json({ error: "Ошибка получения данных" });
    }
  }
);

// Роут для отображения формы редактирования разработки
app.get(
  "/admin/developments/edit/:id",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const developmentId = req.params.id;
      const development = await Development.findByPk(developmentId, {
        include: [
          { model: Category, as: "category" },
          { model: Tag, as: "tags", through: { attributes: [] } },
        ],
      });
      if (!development) {
        return res.status(404).send("Разработка не найдена");
      }
      const categories = await Category.findAll();
      res.json({
        ...development.get(),
        categories: categories.map((category) => category.get()),
        tags: development.tags.map((tag) => tag.get()),
        categoryId: development.categoryId,
      });
    } catch (error) {
      console.error("Ошибка получения разработки для редактирования:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);
// Роут для обработки редактирования разработки
app.post(
  "/admin/developments/edit/:id",
  isAuthenticated,
  hasRole("admin"),
  upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const developmentId = parseInt(req.params.id, 10);
      const { title, description, category_id, tags } = req.body;
      const development = await Development.findByPk(developmentId);

      let previewPath = development.preview;
      let filePath = development.file_path;
      if (req.files) {
        if (req.files["preview"]) {
          previewPath = path
            .join("uploads", path.basename(req.files["preview"][0].path))
            .replace(/\\/g, "/");
        }
        if (req.files["file_path"]) {
          filePath = path
            .join("uploads", path.basename(req.files["file_path"][0].path))
            .replace(/\\/g, "/");
        }
      }
      await development.update({
        title,
        description,
        categoryId: category_id,
        file_path: filePath,
        preview: previewPath,
      });
      if (tags && tags.length > 0) {
        const tagIds = Array.isArray(tags) ? tags : tags.split(",").map(Number);
        await development.setTags(tagIds);
      } else {
        await development.setTags([]);
      }
      const updatedDevelopment = await Development.findByPk(developmentId, {
        include: [
          { model: Category, as: "category" },
          { model: Tag, as: "tags", through: { attributes: [] } },
        ],
      });
      res.json({
        ...updatedDevelopment.get(),
        category: updatedDevelopment.category
          ? updatedDevelopment.category.get()
          : null,
        tags: updatedDevelopment.tags
          ? updatedDevelopment.tags.map((tag) => tag.get())
          : [],
      });
    } catch (error) {
      console.error("Ошибка редактирования разработки:", error);
      res.status(500).send("Internal Server Error");
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

// Функция для получения списка категорий для пользователя
app.get("/user/categories", async (req, res) => {
  try {
    const categories = await Category.findAll();
    res.status(200).json(categories);
  } catch (error) {
    console.error("Ошибка получения категорий:", error);
    res.status(500).send("Ошибка сервера");
  }
});

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
          attributes: ["title", "description", "id", "preview"],
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
