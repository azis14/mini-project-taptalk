package main

import (
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

const SecretKey = "secret"

func main() {
	dsn := "host=localhost user=taptalk password=taptalk dbname=taptalk port=5432 sslmode=disable TimeZone=Asia/Jakarta"
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Couldn't connect to database")
	}

	type User struct {
		Id        uint   `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email" gorm:"unique"`
		Passsword []byte `json:"-"`
	}

	DB = connection

	connection.AutoMigrate(&User{})

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World 👋!")
	})

	app.Post("/api/register", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

		user := User{
			Name:      data["name"],
			Email:     data["email"],
			Passsword: password,
		}

		DB.Create(&user)

		return c.JSON(user)
	})

	app.Post("/api/login", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		var user User

		DB.Where("email = ?", data["email"]).First(&user)

		if user.Id == 0 {
			c.Status(fiber.StatusNotFound)
			return c.JSON(fiber.Map{
				"message": "user not found",
			})
		}

		if err := bcrypt.CompareHashAndPassword(user.Passsword, []byte(data["password"])); err != nil {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"message": "incorrect password",
			})
		}

		claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
			Issuer:    strconv.Itoa(int(user.Id)),
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 1 day
		})

		token, err := claims.SignedString([]byte(SecretKey))

		if err != nil {
			c.Status(fiber.StatusInternalServerError)
			return c.JSON(fiber.Map{
				"message": "could not login",
			})
		}

		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	app.Get("/api/user", func(c *fiber.Ctx) error {
		cookie := c.Cookies("jwt")

		token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

		if err != nil {
			c.Status(fiber.StatusUnauthorized)
			return c.JSON(fiber.Map{
				"message": "unauthenticated",
			})
		}

		claims := token.Claims.(*jwt.StandardClaims)

		var user User

		DB.Where("id = ?", claims.Issuer).First(&user)

		return c.JSON(user)
	})

	app.Post("/api/logout", func(c *fiber.Ctx) error {
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)

		return c.JSON(fiber.Map{
			"message": "success",
		})
	})

	app.Listen(":8080")
}
