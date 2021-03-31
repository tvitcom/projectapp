package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	// "log"
	"fmt"
	"net/http"
	//"time"
)

func mwAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func mwIsUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		v := session.Get("user_id")
		fmt.Println("DEBUG:mwIsUser():", c.Request.URL.Path, "v:", v)
		if v != nil /*&& v.(int64) > 0*/ {
			fmt.Println("DEBUG:mwIsUser() Now user logged:v.(int64)= ", v)
			c.Redirect(http.StatusMovedPermanently, "/user/")
			c.Abort()
		}
		c.Next()
	}
}

func mwIsNotUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		v := session.Get("user_id")
		fmt.Println("DEBUG:mwIsNotUser()", c.Request.URL.Path, "v:", v)
		if v == nil /*&& v.(int64) > 0*/ {
			fmt.Println("DEBUG:mwIsNotUser() v=nil")
			c.Redirect(http.StatusMovedPermanently, "/auth/passwordrecover/")
			c.Abort()
		}
		c.Next()
	}
}

func confCORS(c *gin.Context) {
	// c.Header("server", WEBSERV_NAME)
	// Content-Security-Policy:
	//     default-src 'self';
	//     connect-src 'self' https://sentry.prod.mozaws.net;
	//     font-src 'self' https://addons.cdn.mozilla.net;
	//     frame-src 'self' https://ic.paypal.com https://paypal.com
	//     img-src 'self' data: blob: https://www.paypal.com https://ssl.google-analytics.com
	//     media-src https://videos.cdn.mozilla.net;
	//     object-src 'none';
	//     script-src 'self' https://addons.mozilla.org
	//     style-src 'self' 'unsafe-inline' https://addons.cdn.mozilla.net;
	//     report-uri /__cspreport__
	c.Header("Content-Security-Policy", `
		default-src 'self';
	    connect-src 'self';
	    font-src 'self' https://fonts.gstatic.com;
	    frame-src 'self' https://www.google.com/recaptcha/ https://www.google.com/maps/;
	    img-src 'self' https://lh3.googleusercontent.com/ https://images.unsplash.com data: blob: 'self' https://source.unsplash.com;
	    object-src 'self';
	    script-src 'self' 'unsafe-inline' 'unsafe-eval';
	    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    `)

	if c.Request.Method == "OPTIONS" {
		if len(c.Request.Header["Access-Control-Request-Headers"]) > 0 {
			c.Header("Access-Control-Allow-Headers", c.Request.Header["Access-Control-Request-Headers"][0])
		}
		c.AbortWithStatus(http.StatusOK)
	}
}

func mwCaptcha() gin.HandlerFunc {
	return func(c *gin.Context) {
		// var w http.ResponseWriter = c.Writer
		// var req *http.Request = c.Req
		// captcha.Server(captcha.StdWidth, captcha.StdHeight)
		// before request

		c.Next()

		// after request
	}
}
