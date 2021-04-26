package main

import (
	"strconv"
	"time"

	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"

	// "gorm.io/driver/postgres"
	// "gorm.io/gorm"

	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "taptalk"
	password = "taptalk"
	dbname   = "taptalk"
)

const SecretKey = "secret"

func main() {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)

	if err != nil {
		panic(err)
	}

	defer db.Close()

	err = db.Ping()

	if err != nil {
		panic(err)
	}

	type User struct {
		Id        uint   `json:"id"`
		Username  string `json:"username"`
		Fullname  string `json:"fullname"`
		Birthday  string `json:"birthday"`
		Email     string `json:"email" gorm:"unique"`
		Passsword []byte `json:"-"`
		Name      string `json:"name"`
	}

	type Diary struct {
		Id        uint      `json:"id"`
		Post      string    `json:"post"`
		CreatedAt time.Time `json:"created_at"`
		UserId    int       `json:"user_id"`
	}

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

		var (
			upp, low, num, sym bool
			total              uint8
			msg                string
		)

		for _, char := range data["password"] {
			switch {
			case unicode.IsUpper(char):
				upp = true
				total++
			case unicode.IsLower(char):
				low = true
				total++
			case unicode.IsNumber(char):
				num = true
				total++
			case unicode.IsPunct(char) || unicode.IsSymbol(char):
				sym = true
				total++
			default:
				c.Status(fiber.StatusBadRequest)
				return c.JSON(fiber.Map{
					"message": "password contain invalid character",
				})
			}
		}

		if !upp {
			msg = "password must contain at least one uppercase"
		}
		if !low {
			msg = "password must contain at least one lowercase"
		}
		if !num {
			msg = "password must contain at least one number"
		}
		if !sym {
			msg = "password must contain at least one special character"
		}
		if total < 6 || total > 32 {
			msg = "password length must between 6-32 character"
		}

		if !upp || !low || !num || !sym || total < 6 || total > 32 {
			c.Status(fiber.StatusBadRequest)
			return c.JSON(fiber.Map{
				"message": msg,
			})
		}

		password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

		user := User{
			Fullname:  data["fullname"],
			Username:  data["username"],
			Birthday:  data["birthday"],
			Email:     data["email"],
			Name:      data["name"],
			Passsword: password,
		}

		// DB.Create(&user)

		sqlStatement := `
		INSERT INTO users (fullname, username, birthday, email, passsword, name)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`

		id := 0
		err = db.QueryRow(sqlStatement, user.Fullname, user.Username, user.Birthday, user.Email, user.Passsword, user.Name).Scan(&id)

		if err != nil {
			panic(err)
		}

		return c.JSON(user)
	})

	app.Post("/api/login", func(c *fiber.Ctx) error {
		var data map[string]string

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		var user User

		if len(data["email"]) > 0 {
			// DB.Where("email = ?", data["email"]).First(&user)
			sqlStatement := `SELECT id, email, passsword FROM users WHERE email=$1 LIMIT 1;`
			row := db.QueryRow(sqlStatement, data["email"])
			// err := row.Scan(&user.Id, &user.Fullname, &user.Username, &user.Email, &user.Birthday, &user.Passsword, &user.Name)
			err := row.Scan(&user.Id, &user.Email, &user.Passsword)

			switch err {
			case sql.ErrNoRows:
				c.Status(fiber.StatusNotFound)
				return c.JSON(fiber.Map{
					"message": "email not found",
				})
			case nil:
				fmt.Println(user)
			default:
				panic(err)
			}

		} else if len(data["username"]) > 0 {
			sqlStatement := `SELECT id, username, passsword FROM users WHERE username=$1 LIMIT 1;`
			row := db.QueryRow(sqlStatement, data["username"])
			err := row.Scan(&user.Id, &user.Username, &user.Passsword)
			// err := row.Scan(&user.Id, &user.Fullname, &user.Username, &user.Email, &user.Birthday, &user.Passsword, &user.Name)

			switch err {
			case sql.ErrNoRows:
				c.Status(fiber.StatusNotFound)
				return c.JSON(fiber.Map{
					"message": "username not found",
				})
			case nil:
				fmt.Println(user)
			default:
				panic(err)
			}
		}

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

		// DB.Where("id = ?", claims.Issuer).First(&user)
		sqlStatement := `SELECT * FROM users WHERE id=$1 LIMIT 1;`
		row := db.QueryRow(sqlStatement, claims.Issuer)
		err2 := row.Scan(&user.Id, &user.Fullname, &user.Username, &user.Email, &user.Birthday, &user.Passsword, &user.Name)

		switch err2 {
		case sql.ErrNoRows:
			fmt.Println("No rows were returned!")
		case nil:
			fmt.Println(user)
		default:
			panic(err)
		}

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

	app.Post("/api/post", func(c *fiber.Ctx) error {
		var data map[string]string
		cookie := c.Cookies("jwt")

		if err := c.BodyParser(&data); err != nil {
			return err
		}

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

		// DB.Where("id = ?", claims.Issuer).First(&user)
		sqlStatement := `SELECT id FROM users WHERE id=$1 LIMIT 1;`
		row := db.QueryRow(sqlStatement, claims.Issuer)
		err2 := row.Scan(&user.Id)

		if err2 != nil {
			panic(err2)
		}

		diary := Diary{
			Post:      data["post"],
			CreatedAt: time.Now(),
			UserId:    int(user.Id),
		}

		// // DB.Create(&user)

		sqlStatement2 := `
		INSERT INTO diary (post, created_at, userid)
		VALUES ($1, $2, $3)
		RETURNING id`

		id := 0
		err = db.QueryRow(sqlStatement2, diary.Post, diary.CreatedAt, diary.UserId).Scan(&id)

		if err != nil {
			panic(err)
		}

		// DB.Where("id = ?", claims.Issuer).First(&user)

		return c.JSON(diary)
	})

	app.Post("/api/get-diary", func(c *fiber.Ctx) error {
		var data map[string]string
		cookie := c.Cookies("jwt")

		if err := c.BodyParser(&data); err != nil {
			return err
		}

		_, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

		if err != nil {
			c.Status(fiber.StatusUnauthorized)
			return c.JSON(fiber.Map{
				"message": "unauthenticated",
			})
		}

		// claims := token.Claims.(*jwt.StandardClaims)

		var diary Diary
		// var user User

		// sqlStatement := `
		// SELECT d.id, d.post, d.created_at, u.fullname FROM diary AS d
		// JOIN user AS u ON d.userid = u.id
		// WHERE EXTRACT(year FROM created_at) = $1
		// AND EXTRACT(quarter FROM created_at) = $2
		// AND u.id = $3;`

		sqlStatement := `
		SELECT id, post, created_at FROM diary
		WHERE EXTRACT(year FROM created_at) = $1;`

		row := db.QueryRow(sqlStatement, data["year"])
		return c.JSON(row)
		err2 := row.Scan(&diary.Id, &diary.Post, &diary.CreatedAt)

		switch err2 {
		case sql.ErrNoRows:
			return c.JSON(fiber.Map{
				"message": "data not available",
			})
		case nil:
			// return c.JSON(fiber.Map{
			// 	"writer":     user.Fullname,
			// 	"post":       diary.Post,
			// 	"created_at": diary.CreatedAt,
			// })
			return c.JSON(row)
		default:
			panic(err)
		}
	})

	app.Listen(":8080")
}
