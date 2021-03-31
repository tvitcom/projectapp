package main

import (
	"encoding/json"
	"fmt"
	"github.com/cnjack/throttle"
	"regexp"
	// "github.com/dchest/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"io/ioutil"
	"log"
	storage "my.localhost/funny/projectapp/providers"
	"net/http"
	"os"
	"time"
)

var (
	MAIL_SMTPHOST        string
	MAIL_SMTPPORT        string
	MAIL_USERNAME        string
	MAIL_PASSWORD        string
	KEY32                string
	LOGS_PATH            string
	SSLKEYS_PATH         string
	WEBSERV_NAME         string
	BROWSER_LANG         string
	STORAGE_DRV          string
	STORAGE_DSN          string
	APP_ENTRYPOINT       string
	APP_BRANDNAME        string
	APP_FQDN             string
	APP_FQDN_ADDITIONAL  string
	APP_FQDN_ADDITIONAL2 string
	APP_SSL_ENTRYPOINT   string
	GOOGLE_CREDFILE      string
	GOOGLE_REDIRURL      string
	ADMIN_USER           string
	ADMIN_EMAIL          string
	ADMIN_PASSWORD       string
	BIZ_NAME             string
	BIZ_SHORTNAME        string
	BIZ_EMAIL            string
	BIZ_PHONE            string
	BIZ_PHONE2           string
	BIZ_LOGO             string
	cliCredential        GoogleOauth2ClientCredentials
	oauthConf            *oauth2.Config
	oauthState           string
)

type (
	BizInfo struct {
		Name, ShortName, Email, Phone, Phone2 string
	}
	Seo struct {
		Jsonld      string
		Og          *OG
		Description string
		Keywords    string
	}
	OG struct { // Open Graph basic struct for SEO
		Title, Description, Type, Url, Image string
	}
	UserInfo struct {
		user_id  int64
		Name     string
		Picture  string
		Roles    []string
		Phone    string
		Email    string
		Birthday string
		Data     interface{}
	}
	PageData struct {
		Name             string
		Lang             string
		BaseUrl          string
		Seo              *Seo
		Biz              *BizInfo
		User             *UserInfo
		LeftMenuSelected int
		Data             interface{}
	}
	SignupForm struct {
		Name           string `form:"name" json:"name" xml:"name"  binding:"required"`
		Phone          string `form:"phone" json:"phone" xml:"phone" binding:"required"`
		Email          string `form:"email" json:"email" xml:"email" binding:"required"`
		Password       string `form:"password" json:"password" xml:"password" binding:"required"`
		PasswordRepeat string `form:"password-repeat" json:"password-repeat" xml:"password-repeat" binding:"required"`
		// CaptchaId       string `form:"captchaId" json:"captchaId" xml:"captchaId"  binding:"required"`
		// CaptchaSolution string `form:"captchaSolution" json:"captchaSolution" xml:"captchaSolution"  binding:"required"`
	}
	LoginForm struct {
		Login    string `form:"login" json:"login" xml:"login"  binding:"required"`
		Password string `form:"password" json:"password" xml:"password" binding:"required"`
	}
	// Types for authentiacted user by google oauth2
	GoogleOauth2ClientCredentials struct {
		Cid     string `json:"cid"`
		Csecret string `json:"csecret"`
	}
	GoogleUser struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Locale        string `json:"gender"`
	}
)

func init() {
	// loading .env settings 
	err := godotenv.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	gin.SetMode(os.Getenv("GIN_MODE"))
	APP_BRANDNAME = os.Getenv("app_brandname") // should be withoud finalize dot
	APP_FQDN = os.Getenv("app_fqdn")           // should be withoud finalize dot
	APP_FQDN_ADDITIONAL = os.Getenv("app_fqdn_additional")
	APP_FQDN_ADDITIONAL2 = os.Getenv("app_fqdn_additional2")
	LOGS_PATH = os.Getenv("logs_path")
	WEBSERV_NAME = os.Getenv("webserv_name")
	SSLKEYS_PATH = os.Getenv("sslkeys_path")
	MAIL_SMTPHOST = os.Getenv("mail_smtphost")
	MAIL_SMTPPORT = os.Getenv("mail_smtpport")
	MAIL_USERNAME = os.Getenv("mail_username")
	MAIL_PASSWORD = os.Getenv("mail_password")
	GOOGLE_CREDFILE = os.Getenv("google_credential_file")
	GOOGLE_REDIRURL = "https://" + APP_FQDN + os.Getenv("google_redirect_path")
	APP_ENTRYPOINT = os.Getenv("app_entrypoint")
	APP_SSL_ENTRYPOINT = os.Getenv("app_ssl_entrypoint")
	ADMIN_USER = os.Getenv("admin_user")
	ADMIN_EMAIL = os.Getenv("admin_email")
	ADMIN_PASSWORD = os.Getenv("admin_password")
	STORAGE_DRV = os.Getenv("db_type")
	STORAGE_DSN = os.Getenv("db_user") + ":" + os.Getenv("db_pass") + "@/" + os.Getenv("db_name") + "?parseTime=true"
	KEY32 = os.Getenv("app_secret_key")
	BIZ_NAME = os.Getenv("biz_name")
	BIZ_SHORTNAME = os.Getenv("biz_shortname")
	BIZ_EMAIL = os.Getenv("biz_email")
	BIZ_PHONE = os.Getenv("biz_phone")
	BIZ_PHONE2 = os.Getenv("biz_phone2")
	BIZ_LOGO = os.Getenv("biz_logo")

	//Google oauth2 init
	googlecredential, err := ioutil.ReadFile("./data/credentials.json")
	if err != nil {
		log.Printf("File error: %v\n", err)
		os.Exit(1)
	}
	json.Unmarshal(googlecredential, &cliCredential)

	oauthConf = &oauth2.Config{
		ClientID:     cliCredential.Cid,
		ClientSecret: cliCredential.Csecret,
		RedirectURL:  GOOGLE_REDIRURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",   // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.profile", // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		},
		Endpoint: google.Endpoint,
	}
}

func main() {
	db, err := storage.NewConnection(STORAGE_DRV, STORAGE_DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Problem with db connection: %s\n", err)
		os.Exit(1)
	}
	router := gin.New()
	// Define common middlewares
	router.Use(gin.Recovery())
	router.Use(confCORS)

	if gin.Mode() == gin.ReleaseMode {
		gin.DisableConsoleColor()
		// Sett log format:
		f, _ := os.Create(LOGS_PATH)
		gin.DefaultWriter = io.MultiWriter(f)
		fmt.Println("DEBUG MODE: ", gin.IsDebugging())
		fmt.Println("LOGING MODE: Enabled (logs, console, debug messages)")
		router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
			//custom format for logging:
			return fmt.Sprintf("%s - [%s] %s \"%s\" %d \"%s\" %s\n",
				param.TimeStamp.Format("2006-01-02 15:04:05"),
				param.ClientIP,
				param.Method,
				param.Path,
				param.StatusCode,
				param.Request.UserAgent(),
				param.ErrorMessage,
			)
		}))
	} else {
		fmt.Println("DEBUG MODE:gin.Mode():", gin.Mode(), " gin.IsDebugging()=", gin.IsDebugging())
		fmt.Println("LOGING MODE: Disabled: amin_user,admin_password:", ADMIN_USER, ADMIN_PASSWORD)
	}

	// Server settings
	router.Delims("{{", "}}")
	router.LoadHTMLGlob("./templates/*.htmlt")

	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	s := &http.Server{
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 8 << 20,
	}

	// Session store init
	sessionStore := cookie.NewStore([]byte("secretu"), []byte(KEY32))
	router.Use(sessions.Sessions("bin", sessionStore)) //Название ключа в куках

	// Static assets
	router.Static("/public", "./public")
	router.Static("/assets", "./assets")
	router.Static("/userpic", "./filestorage/userpic")
	router.StaticFile("/favicon.ico", "./assets/img/favicon.ico")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "landing.index.htmlt", gin.H{})
	})

	router.GET("/link-for-cast-my-resume", func(c *gin.Context) {
		c.HTML(http.StatusOK, "resume.cast.htmlt", gin.H{})
	})

	router.GET("/page/:name", func(c *gin.Context) {
		page := c.Param("name")
		c.HTML(http.StatusOK, page+"t", gin.H{})
	})

	//auth router group
	auth := router.Group("/auth", mwIsUser(), throttle.Policy(&throttle.Quota{
		Limit:  60,
		Within: time.Minute,
	}))
	// login
	auth.GET("/login", func(c *gin.Context) {
		hasLogin := c.DefaultQuery("hasLogin", "")
		hasPassword := c.DefaultQuery("hasPassword", "")
		//google oauth2 implementation
		var GoogleOAuthLink string = "#"
		oauthState = randToken()
		session := sessions.Default(c)
		session.Set("state", oauthState)
		session.Save()
		GoogleOAuthLink = getLoginURL(oauthState)
		c.HTML(http.StatusOK, "login.htmlt", gin.H{
			"hasLogin":    hasLogin,
			"hasPassword": hasPassword,
			"gOauthLink":  GoogleOAuthLink,
		})
	})
	auth.POST("/login", func(c *gin.Context) {
		email := c.PostForm("login")
		password := c.PostForm("password")
		//validation
		var validStr = regexp.MustCompile(`^[_a-zA-Z0-9]{2,60}@[a-zA-Z0-9]{2,56}.[a-zA-Z]{2,6}$`)
		if ok := validStr.MatchString(email); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid email address"})
			return
		}
		u := storage.GetUserByEmailRoles(db, email, storage.USER)
		DD("DEBUG:u=", u, "dbuser.User_id > 0", bool(u.User_id > 0))
		if u.User_id == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"warn": "user not available"})
			return
		}
		passwordIsValid := IsEqualSaltedSha256(KEY32, password, u.Password_hash)
		DD("DEBUG:email,password,passwordIsValid:", email, password, passwordIsValid)
		DD("DEBUG:HashToDb=", GetSaltedSha256(KEY32, password))
		if u.User_id > 0 && passwordIsValid {
			session := sessions.Default(c)
			session.Set("user_id", u.User_id)
			session.Save()
			c.Redirect(http.StatusMovedPermanently, "/user/")
		} else {
			c.Redirect(http.StatusMovedPermanently, "/auth/passwordrecover/")
		}
		return
	})

	// signup
	auth.GET("/signup", func(c *gin.Context) {
		//Captcha init
		captchaSign := struct {
			CaptchaId string
		}{
			// captcha.New(),
		}

		var GoogleOAuthLink string = "/soon"
		oauthState = randToken()
		session := sessions.Default(c)
		session.Set("state", oauthState)
		session.Save()
		GoogleOAuthLink = getLoginURL(oauthState)
		c.HTML(http.StatusOK, "register.htmlt", gin.H{"gOauthLink": GoogleOAuthLink, "CaptchaId": captchaSign})
	}, mwCaptcha())

	auth.POST("/signup", func(c *gin.Context) {
		var f SignupForm

		//Validation
		// if !captcha.VerifyString(f.CaptchaId, f.CaptchaSolution) {
		// 	c.String(403, "Wrong captcha solution! No robots allowed!\n")
		// 	return
		// }
		err := c.ShouldBind(&f)
		if err != nil && f.Password != f.PasswordRepeat {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if f.Password != f.PasswordRepeat {
			c.JSON(http.StatusBadRequest, gin.H{"error": "The passwords don't equal"})
			return
		}
		//Normalisation users parameters
		normPhone := PhoneNormalisation(f.Phone)

		var validEmailStr = regexp.MustCompile(`^[_a-zA-Z0-9]{2,60}@[-a-zA-Z0-9]{2,56}.[a-zA-Z]{2,6}$`)
		if ok := validEmailStr.MatchString(f.Email); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid email address"})
			return
		}
		var validPhoneStr = regexp.MustCompile(`^[0-9]{10,12}$`)
		if ok := validPhoneStr.MatchString(normPhone); !ok {
			c.JSON(http.StatusBadRequest, gin.H{"warn": "invalid phonenumber"})
			return
		}

		//Check values into db:
		if user_id := storage.IsUserByPhonenumber(db, normPhone); user_id > 0 {
			c.JSON(http.StatusPreconditionFailed, gin.H{"warn": "bad phonenumber for registration"})
			return
		}

		// Find formEmail into database:
		user := storage.GetUserByEmailOnly(db, f.Email)
		if user.User_id > 0 {
			c.JSON(http.StatusPreconditionFailed, gin.H{"warn": "bad email for registration"})
			return
		}

		u := storage.User{}
		/*UserTemplate struct {
		User_id      int64
		Name            string
		Email           string
		Phone           string
		Messenger       string
		Auth_key        string
		Password_hash   string
		Approve_token   string
		Picture 	 	string
		Birthday      string
		Updated       int64
		Lastlogin     int64
		Roles     string
		}*/
		u.Name = GetEmailsAlias(f.Email)
		u.Email = f.Email
		u.Phone = normPhone
		u.Messenger = ""
		u.Auth_key = ""
		u.Password_hash = GetSaltedSha256(KEY32, f.Password)
		u.Updated = time.Now().Unix()
		u.Approve_token = GetSaltedSha256(KEY32, u.Email)
		u.Roles = storage.NOUSER
		link, _ := storage.NewUserWithApproveToken(db, u)

		//Approve_token by mail:
		// Send link to user email:
		tplFile := "./email/approvement.emlt"
		emailData := struct {
			From       string
			Brand      string
			Name       string
			ApproveURL string
		}{
			From:       MAIL_USERNAME,
			Brand:      APP_BRANDNAME,
			Name:       u.Name,
			ApproveURL: "https://" + APP_FQDN + "/auth/approvement/" + link + "?login=" + u.Email,
		}

		err = SendSmtpMailByPlainAuth(MAIL_SMTPHOST, MAIL_SMTPPORT, MAIL_USERNAME, MAIL_PASSWORD, u.Email, tplFile, emailData)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Emailed: ok")
		}
		// TODO: work user without approving own link...maybe captcha need
		// Setting user_id into session
		// c.HTML(http.StatusOK, "dashboard.htmlt", gin.H{})

		//Redirect to user personal message:
		c.Redirect(http.StatusMovedPermanently, "/message:You should check your email and folowing by our link")
		return
	})

	// approvement new signed user
	auth.GET("/approvement/:secretlink", func(c *gin.Context) {
		login := c.Query("login")
		lnk := c.Param("secretlink")
		affected := storage.ApproveNewUser(db, login, lnk, storage.USER)
		fmt.Println("DEBUG:ApproveNewUser:return affecte", affected)
		//Set session user_id
		if affected > 0 {
			u := storage.GetUserByEmailRoles(db, login, storage.USER)
			if u.User_id > 0 {
				session := sessions.Default(c)
				session.Set("user_id", u.User_id)
				session.Save()
				c.Redirect(http.StatusMovedPermanently, "/user/")
				return
			}
		}
		c.JSON(http.StatusPreconditionFailed, gin.H{"warn": "bad link for approve email"})
		return
	})
	// restorepassword
	auth.GET("/passwordrecover", func(c *gin.Context) {
		c.HTML(http.StatusOK, "forgot-password.htmlt", gin.H{})
	})

	auth.POST("/passwordrecover", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})

	auth.GET("/passwordrecovered/:secretlink", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})

	//oauth router group
	oauth := router.Group("/oauth", throttle.Policy(&throttle.Quota{
		Limit:  4,
		Within: time.Minute,
	}))
	oauth.GET("/googleuser", func(c *gin.Context) {
		// Request to Google about google account base user information
		// Handle the exchange code to initiate a transport.
		googleUser := GoogleUser{}
		session := sessions.Default(c)
		retrievedState := session.Get("state")
		if retrievedState != c.Query("state") {
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		tok, err := oauthConf.Exchange(oauth2.NoContext, c.Query("code"))
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		client := oauthConf.Client(oauth2.NoContext, tok)
		gAccount, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		defer gAccount.Body.Close()
		data, err := ioutil.ReadAll(gAccount.Body)
		if err != nil {
			c.AbortWithError(http.StatusPreconditionFailed, err)
			return
		}
		fmt.Println("gAccount (google says): ", string(data))

		err = json.Unmarshal(data, &googleUser)
		if err != nil {
			log.Fatalln("error:", err)
		}
		fmt.Println("DEBUG:googleUser.email: ", googleUser.Email)

		//Check if user yet not database
		dbuser := storage.GetUserByEmailOnly(db, googleUser.Email)
		fmt.Println("DEBUG:googleUser: Check ifUser from db:", dbuser)
		if dbuser.User_id == 0 {
			u := storage.User{}
			u.Name = googleUser.Name
			u.Email = googleUser.Email
			u.Phone = ""
			u.Picture = googleUser.Picture
			u.Password_hash = GetSaltedSha256(KEY32, KEY32) // Dummy password Only for secrecy
			u.Updated = time.Now().Unix()
			u.Approve_token = "" // Dummy token Only for secrecy
			u.Roles = storage.USER
			link, user_id := storage.NewUserWithApproveToken(db, u)
			DD("DEBUG:/signup POST: u.Password_hash, link", user_id, link)
			session.Set("user_id", user_id)
		} else {
			session.Set("user_id", dbuser.User_id)
		}
		session.Save()
		c.Redirect(http.StatusMovedPermanently, "/user/")
	})

	admin := router.Group("/admin", throttle.Policy(&throttle.Quota{
		Limit:  60,
		Within: time.Minute,
	}))

	admin.Use(gin.BasicAuth(gin.Accounts{
		ADMIN_USER: ADMIN_PASSWORD,
	}))

	admin.GET("/", func(c *gin.Context) {
		// get user, it was set by the BasicAuth middleware
		user := c.MustGet(gin.AuthUserKey).(string)
		fmt.Println("DEBUG: /admin: user", user)
		c.HTML(http.StatusOK, "admin.dashboard.htmlt", gin.H{})
	})
	// users listing
	// support messages
	admin.GET("/support", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})

	// User part
	user := router.Group("/user", mwIsNotUser())

	user.GET("/", func(c *gin.Context) {
		//Make Page Data
		pd := new(PageData)
		pd.Name = "Dashboard"
		pd.BaseUrl = "/user/"
		pd.Lang = GetBrowserLang()
		pd.Biz = GetBizInfo()
		pd.Seo = GetSeoDefault(c, pd.Name, "", "", "", BIZ_LOGO)
		pd.User = GetUserInfo(c, db)
		c.HTML(http.StatusOK, "dashboard.htmlt", gin.H{"Page": pd})
	})

	user.GET("/profile", func(c *gin.Context) {

		//Make Page Data
		pd := new(PageData)
		pd.Name = "Profile"
		pd.BaseUrl = "/user/"
		pd.Lang = GetBrowserLang()
		pd.Biz = GetBizInfo()
		pd.Seo = GetSeoDefault(c, pd.Name, "", "", "", BIZ_LOGO)
		pd.User = GetUserInfo(c, db)
		c.HTML(http.StatusOK, "profile.htmlt", gin.H{"Page": pd})
	})

	user.POST("/profile", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})

	user.POST("/profile/changepassword", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})

	// Logout:
	user.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		// user_id := session.Get("user_id")
		session.Set("user_id", nil)
		session.Save()
		session.Clear()
		c.Redirect(http.StatusMovedPermanently, "/auth/login")
		return
	})

	user.GET("/signout", func(c *gin.Context) {
		session := sessions.Default(c)
		log.Println("running SignOut for user_id:", session.Get("user_id"))
		session.Set("user_id", nil)
		session.Save()
		DD("Session set to: nil")
		session.Clear()
		DD("User Is deleted!!!!")
		c.Redirect(http.StatusMovedPermanently, "/auth/login")
		return
	})

	corp := router.Group("/corp", mwIsNotUser())

	corp.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	}, mwIsUser())

	router.POST("/support", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/soon")
		return
	})
	router.GET("/soon", func(c *gin.Context) {
		c.HTML(http.StatusServiceUnavailable, "soon.htmlt", gin.H{})
	})
	router.GET("/error:num", func(c *gin.Context) {
		errCode := c.Param("num")
		c.HTML(http.StatusOK, "error.htmlt", gin.H{"errCode": errCode})
	})
	router.GET("/message:text", func(c *gin.Context) {
		userMessage := c.Param("text")
		c.HTML(http.StatusOK, "message.htmlt", gin.H{"userMessage": userMessage})
	})

	router.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "error.htmlt", gin.H{})
	})
	router.NoMethod(func(c *gin.Context) {
		c.String(http.StatusMethodNotAllowed, `405 MethodNotAllowed`)
	})

	// Listen and serve:
	// if !gin.IsDebugging() {
	// 	fmt.Println("SERVER MODE: http+https")
	// 	go func() {
	// 		if err := http.ListenAndServe(APP_ENTRYPOINT, http.HandlerFunc(redirectHTTPS)); err != nil {
	// 			log.Fatalf("ListenAndServe error: %v", err)
	// 		}
	// 	}()
	// 	router.RunTLS(APP_SSL_ENTRYPOINT, SSLKEYS_PATH+"cert1.pem", SSLKEYS_PATH+"privkey1.pem")

	// } else {
	s.Addr = APP_ENTRYPOINT
	fmt.Println("SERVER MODE: without https")
	err = s.ListenAndServe()
	if err != nil {
		log.Fatalf("ListenAndServe error: %v", err)
	}
	// }
}
