package providers

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
	// "time"
)

var (
	db *sql.DB
)
const (
	ADMIN = "a"
	MODER = "m"
	USER = "u"
	NOUSER = "n"
)
//Define modules behaviors:
type (
	UserTemplate struct {
		Name, Phone, Email, Password_hash, Approve_token string
		Updated int64
	}
	User struct {
		User_id       int64
		Name          string
		Email         string
		Phone         string
		Messenger     string
		Auth_key      string
		Password_hash string
		Approve_token string
		Picture 	  string
		Birthday      string
		Updated       int64
		Lastlogin     int64
		Roles         string
	}
	Storage interface {
		NewConnection(drv, dsn string) (*sql.DB, error)
		UpdateLastLogintime(db *sql.DB, user_id int64) (err error)
		UpdateProfileTime(db *sql.DB) (err error)

		//    mwAdmin(): (user_id>0) => ->-> "/admin"
		GetUserById(db *sql.DB, user_id int64) (User)
		GetUsersPaged(db *sql.DB, limit int, offset int) ([]User, error) //SELECT * FROM users ORDER BY id DESC LIMIT 10 OFFSET 5

		//    mwGuest(): (user_id>0) => ->-> "/user"
		//    mwAccount(): (user_id==0) => ->-> "/guest/signup"

		// /#signup:GET                 - Форма регистрации пользователя сайта PhotoSet,
		//    /guest/signup:POST           - Регистрация пользователя сайта PhotoSet,
		NewUserWithApproveToken(db *sql.DB, u User) (newApproveToken string,lastId int64)

		//    /guest/approvement:GET       - Подтверждение почты или телефона пользователя,
		ApproveNewUser(db *sql.DB, email ,link, setRole string) int64

		//    /guest/auth/@guestlink:GET    - Форма ввода телефона пользователя перешедшего по ссылке гостя.
		//    /guest/login:GET|POST        - Логин - аутентификация и авторизация пользователя,
		IsUserByPhonenumber(db *sql.DB, phone string) int64
		GetUserByEmailOnly(db *sql.DB, email string) User
		GetUserByEmailRoles(db *sql.DB, email, roles string) User
		

		//    /guest/password/request:GET     - Запрос восстановления пароля пользователя,
		//    /guest/password/validation/@link:GET  - Подтверждение восстановления пароля пользователя,
		GetRecoverPasswordLink(db *sql.DB, recoverChannel string) (recoverApproveToken string, err error)
		ApproveRecoverPassword(db *sql.DB, link string) (User, error)

		//   /user/signout/request:GET           - Запрос удаления аккаунта.
		//   /user/signout/validation/@link:GET   - Подтверждение удаления аккаунта.
		DeleteUser(db *sql.DB, user_id int64) (deleteApproveToken string, err error)
		ApproveDeleteUser(db *sql.DB, link string) (User, error)

		//   /user/gdprinfo:GET                   - GDPR Информация о аккаунте.
		GetGdprUserInfo(db *sql.DB, user_id int64) (User, err error)

		// /user/logout:GET|POST                - Выход.
		// /user/profile:GET|POST      - Редактирование профиля пользователя.
		UpdateUserInfo(db *sql.DB, u User) (rowCnt int64)
	}
)

func NewConnection(drv, dsn string) (*sql.DB, error) {
	db, err := sql.Open(drv, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if err = db.Ping(); err != nil {
		os.Exit(1)
	}
	return db, nil
}

func IsUserByPhonenumber(db *sql.DB, phone string) int64 {
	sqlStatement := `SELECT user_id FROM user WHERE phone = ?`
	var u User
	row := db.QueryRow(sqlStatement, phone)
	err := row.Scan(
		&u.User_id,
	)
	switch err {
		case sql.ErrNoRows:
			return 0
		case nil:
			return u.User_id
		default:
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
	}
	return 0
}

func GetUserById(db *sql.DB, id int64) User {
	sqlStatement := `SELECT user_id, name, email, phone, messenger, auth_key, password_hash, approve_token, picture, birthday, updated, lastlogin, roles 
	FROM user WHERE user_id =  ?`
	var u User
	row := db.QueryRow(sqlStatement, id)
	err := row.Scan(
		&u.User_id,
		&u.Name,
		&u.Email,
		&u.Phone,
		&u.Messenger,
		&u.Auth_key,
		&u.Password_hash,
		&u.Approve_token,
		&u.Picture,
		&u.Birthday,
		&u.Updated,
		&u.Lastlogin,
		&u.Roles,
	)
	switch err {
		case sql.ErrNoRows:
			fmt.Println("No rows were returned!")
			return u
		case nil:
			return u
		default:
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
	}
	return u
}

func GetUserByEmailOnly(db *sql.DB, email string) User {
	sqlStatement := `SELECT user_id, name, email, phone, messenger, auth_key, password_hash, approve_token, picture, birthday, updated, lastlogin, roles 
	FROM user WHERE email =  ?`
	var u User
	row := db.QueryRow(sqlStatement, email)
	err := row.Scan(
		&u.User_id,
		&u.Name,
		&u.Email,
		&u.Phone,
		&u.Messenger,
		&u.Auth_key,
		&u.Password_hash,
		&u.Approve_token,
		&u.Picture,
		&u.Birthday,
		&u.Updated,
		&u.Lastlogin,
		&u.Roles,
	)
	switch err {
		case sql.ErrNoRows:
			fmt.Println("No rows were returned!")
			return u
		case nil:
			return u
		default:
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
	}
	return u
}

func GetUserByEmailRoles(db *sql.DB, email, roles string) User {
	sqlStatement := `SELECT user_id, name, email, phone, messenger, auth_key, password_hash, approve_token, picture, birthday, updated, lastlogin, roles 
	FROM user WHERE email = ? and roles = ?`
	var u User
	row := db.QueryRow(sqlStatement, email, roles)
	err := row.Scan(
		&u.User_id,
		&u.Name,
		&u.Email,
		&u.Phone,
		&u.Messenger,
		&u.Auth_key,
		&u.Password_hash,
		&u.Approve_token,
		&u.Picture,
		&u.Birthday,
		&u.Updated,
		&u.Lastlogin,
		&u.Roles,
	)
	switch err {
		case sql.ErrNoRows:
			fmt.Println("No rows were returned!")
			return u
		case nil:
			return u
		default:
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
	}
	return u
}

func GetAllUsers(db *sql.DB) ([]*User, error) {
	rows, err := db.Query("SELECT user_id, name, email, phone, messenger, auth_key, password_hash, approve_token, picture, birthday, updated, lastlogin, roles FROM user")
	if err != nil {
		// return nil, err
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		u := new(User)
		err := rows.Scan(
			&u.User_id,
			&u.Name,
			&u.Email,
			&u.Phone,
			&u.Messenger,
			&u.Auth_key,
			&u.Password_hash,
			&u.Approve_token,
			&u.Picture,
			&u.Birthday,
			&u.Updated,
			&u.Lastlogin,
			&u.Roles,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	return users, nil
}

// Paged data using: 
// storage as providers imported!!!
// limit, _ := strconv.ParseInt(c.DefaultQuery("limit", "100"), 10, 64)
// offset, _ := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 64)
// users, err := storage.GetUsersPaged(db, limit, offset)
func GetUsersPaged(db *sql.DB, limit int64, offset int64) ([]*User, error) {
	rows, err := db.Query("SELECT user_id, name, email, password, roles  FROM user ORDER BY user_id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		u := new(User)
		err := rows.Scan(
			&u.User_id,
			&u.Name,
			&u.Email,
			&u.Password_hash,
			&u.Roles,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	return users, nil
}
// Return rows affected only!!!
func ApproveNewUser(db *sql.DB, email , token, setRole string) int64 {
    stmt, err := db.Prepare(`update user set approve_token = "", roles = ? where email = ? and approve_token = ?`)
    defer stmt.Close()
	if err != nil {
		log.Panicln(err)
	}
	res, err := stmt.Exec(setRole, email, token)
	if err != nil {
		log.Panicln(err)
	}
	rowCnt, err := res.RowsAffected()
	if err != nil {
		log.Panicln(err)
	}
	return rowCnt
}

func NewUserWithApproveToken(db *sql.DB, u User) (newApproveToken string, lastId int64){
    stmt, err := db.Prepare(`
		INSERT INTO user(user_id, name, email, phone, password_hash, approve_token, updated, roles) 
		VALUES
		(null, ?, ?, ?, ?, ?, ?, ?);
    `)
    defer stmt.Close()
	if err != nil {
		log.Panicln(err)
	}
	res, err := stmt.Exec(u.Name, u.Email, u.Phone, u.Password_hash, u.Approve_token, u.Updated, u.Roles)
	if err != nil {
		log.Panicln(err)
	}
	lastId, err = res.LastInsertId()
	if err != nil {
		log.Panicln(err)
	}
	// rowCnt, err := res.RowsAffected()
	// if err != nil {
	// 	log.Panicln(err)
	// }
	// log.Println("RowsAffected():",rowCnt)
	return u.Approve_token, lastId
}

func UpdateUserInfo(db *sql.DB, u User) (rowCnt int64){
    stmt, err := db.Prepare(`UPDATE user SET 
    	name=?, email= ?, phone=?, password_hash=?, picture=?, birthday=?, updated=? where user_id=?;
    `)
    defer stmt.Close()
	if err != nil {
		log.Panicln(err)
	}
	res, err := stmt.Exec(u.Name, u.Email, u.Phone, u.Password_hash, u.Picture, u.Updated, u.User_id)
	if err != nil {
		log.Panicln(err)
	}
	// lastId, err = res.LastInsertId()
	// if err != nil {
	// 	log.Panicln(err)
	// }
	rowCnt, err = res.RowsAffected()
	if err != nil {
		log.Panicln(err)
	}
	return rowCnt
}