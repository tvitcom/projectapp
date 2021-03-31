package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"html/template"
	storage "my.localhost/funny/projectapp/providers"
	"net/http"
	"net/smtp"
	"strings"
)

func GetSha256(text string) string {
	h := sha256.New()
	h.Write([]byte(text))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func GetSaltedSha256(salt, password string) string {
	return GetSha256(salt + password)
}

func IsEqualSaltedSha256(salt, password, hashDatabase string) bool {
	saltedPasswordHash := GetSaltedSha256(salt, password)
	// DD("DEBUG:saltedPasswordHash", saltedPasswordHash)
	// DD("DEBUG:hashDatabase", hashDatabase)
	if saltedPasswordHash == hashDatabase {
		return true
	}
	return false
}

// Google OAUTH clients functions
func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func getLoginURL(state string) string {
	return oauthConf.AuthCodeURL(state)
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+APP_FQDN+r.RequestURI, http.StatusMovedPermanently)
}

func SendSmtpMailByPlainAuth(smtpHost, smtpPort, fromMail, fromPassword, toMail, tplFile string, mailData interface{}) error {
	to := []string{toMail}
	t, err := template.ParseFiles(tplFile)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, mailData); err != nil {
		return err
	}
	auth := smtp.PlainAuth("", fromMail, fromPassword, smtpHost)
	addr := smtpHost + ":" + smtpPort
	return smtp.SendMail(addr, auth, fromMail, to, buf.Bytes())
}

func PhoneNormalisation(n string) string {
	//remove `()-\b+` in phone number string
	r := strings.NewReplacer("-", "", "(", "", ")", "", "+", "", " ", "")
	return r.Replace(n)
}

func GetUserpicURL(filepath string) string {
	if filepath == "" {
		filepath = "0_60x60.jpeg"
	}
	return "/userpic/" + filepath
}

func GetBizInfo() *BizInfo {
	biz := new(BizInfo)
	biz.ShortName = BIZ_SHORTNAME
	biz.Name = BIZ_NAME
	biz.Email = BIZ_EMAIL
	biz.Phone = BIZ_PHONE
	biz.Phone2 = BIZ_PHONE2
	return biz
}

//TODO: make normal jsonld builder
func GetSeoDefault(c *gin.Context, title, descr, typ, url, logo string) *Seo {
	if url == "" {
		url = c.FullPath()
	}
	if typ == "" {
		typ = "website"
	}
	if descr == "" {
		descr = "simple useful project application for people"
	}
	seo := new(Seo)
	seo.Jsonld = ""
	seo.Og = new(OG)
	seo.Og.Title = title
	seo.Og.Description = descr
	seo.Og.Type = typ
	seo.Og.Url = url
	seo.Og.Image = logo
	seo.Keywords = "simple useful project application for peaple"
	seo.Description = descr
	return seo
}

func GetUserInfo(c *gin.Context, db *sql.DB) *UserInfo {
	info := new(UserInfo)

	// get current user_id
	session := sessions.Default(c)
	uid := session.Get("user_id")

	// get user info from db
	u := storage.GetUserById(db, uid.(int64))
	info.Name = u.Name
	info.Phone = u.Phone
	info.Email = u.Email
	info.Picture = GetUserpicURL(u.Picture)
	return info
}

//TODO : make normal getting browser lang
func GetBrowserLang() string {
	return "en"
}

// import("strings")
func GetEmailsAlias(email string) string {
	splitted := strings.Split(email, "@")
	return splitted[0]
}

// print debug indormation only if debug mode available
func DD(args ...interface{}) {
	debugee := []interface{}{0: "DEBUG:"}
	args = append(debugee, args)
	if gin.IsDebugging() {
		fmt.Println(args...)
	}
}
