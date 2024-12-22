const { Sequelize, DataTypes, Op } = require("sequelize");

const sequelize = new Sequelize("database", "vp", "123", {
  dialect: "sqlite",
  storage: "database.sqlite",
});

// Определение моделей
const User = sequelize.define(
  "User",
  {
    user_id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      // Храните хэшированные пароли! Используйте bcrypt или подобное
      type: DataTypes.STRING,
      allowNull: false,
    },
  },
  {
    timestamps: false,
  }
);

const Development = sequelize.define(
  "Development",
  {
    development_id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
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
    category_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    preview: {
      type: DataTypes.STRING,
    },
    tag_id: {
      // Возможно, нужно изменить на Many-to-Many связь
      type: DataTypes.INTEGER,
    },
    profile_id: {
      type: DataTypes.INTEGER,
    },
  },
  {
    timestamps: false,
  }
);

const Category = sequelize.define(
  "Category",
  {
    category_id: {
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
  {
    timestamps: false,
  }
);

const Tag = sequelize.define(
  "Tag",
  {
    tag_id: {
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
  {
    timestamps: false,
  }
);

const DownloadHistory = sequelize.define(
  "DownloadHistory",
  {
    download_history_id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    development_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    download_date: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.NOW,
    },
  },
  {
    timestamps: false,
  }
);

const Profile = sequelize.define(
  "Profile",
  {
    profile_id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    development_id: {
      type: DataTypes.INTEGER,
    },
    download_history_id: {
      type: DataTypes.INTEGER,
    },
  },
  {
    timestamps: false,
  }
);

// Определение связей (ассоциаций)

User.hasMany(Development, { foreignKey: "user_id" });
Development.belongsTo(User, { foreignKey: "user_id" });

User.hasMany(DownloadHistory, { foreignKey: "user_id" });
DownloadHistory.belongsTo(User, { foreignKey: "user_id" });

Development.belongsTo(Category, { foreignKey: "category_id" });
Category.hasMany(Development, { foreignKey: "category_id" });

User.hasOne(Profile, { foreignKey: "user_id" });
Profile.belongsTo(User, { foreignKey: "user_id" });

DownloadHistory.belongsTo(Profile, { foreignKey: "download_history_id" });

async function run() {
  try {
    await sequelize.sync({ force: true });
    console.log("Таблицы пересозданы.");

    // // Создание пользователей
    // await User.create({ name: "John Doe", age: 30, cash: 100, password: 111 });
    // await User.create({
    //   name: "Jane Smith",
    //   age: 25,
    //   cash: 200,
    //   password: 112,
    // });
    // await User.create({ name: "Oleg", age: 40, cash: 1000, password: 113 });
    // await User.create({ name: "Natasha", age: 19, cash: 500, password: 114 });
  } catch (error) {
    console.error("Ошибка:", error);
  } finally {
    await sequelize.close();
  }
}

run();
