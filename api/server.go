package main

import (
	"fmt"
	"math/rand"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-rennes/oauth2"
)

var uri string

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.GET("/client/", func(c *gin.Context) {
		rndm := fmt.Sprintf("%d", rand.Int())
		oauth2.Cookies = append(oauth2.Cookies, rndm)
		c.HTML(200, "index.html", gin.H{
			"cookie": rndm,
		})
	})

	r.GET("/server_auth/authorize", func(c *gin.Context) {
		//type := c.Query("response_type")
		//client := c.Query("client_id")
		uri = c.Query("redirect_uri")
		c.Redirect(301, "/server_resources/authorize")
	})

	r.GET("/server_resources/authorize", func(c *gin.Context) {
		c.HTML(200, "authorize.html", "")
	})

	r.POST("/server_auth/authorize", func(c *gin.Context) {
		cookie := c.Query("cookie")

		present := false
		for _, item := range oauth2.Cookies {
			if item == cookie {
				present = true
				break
			}
		}

		if !present {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		oauth2.CodeGenerated[cookie] = fmt.Sprintf("%d", rand.Int63())
		c.JSON(200, gin.H{
			"code":         oauth2.CodeGenerated,
			"redirect_uri": uri,
		})
	})

	// 127.0.0.1/token? code=<authorization code> &grant_type=authorization_code &redirect_uri=<redirect URI>

	r.GET("/server_auth/token", func(c *gin.Context) {
		code := c.Query("code")
		redirectURI := c.Query("redirect_uri")

		cookie := c.Query("cookie")

		if code != oauth2.CodeGenerated[cookie] {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Invalid code %s expected %s", code, oauth2.CodeGenerated)})
			return
		}
		oauth2.AccessCode[cookie] = fmt.Sprintf("%d", rand.Int63())

		c.JSON(200, gin.H{
			"code":         oauth2.AccessCode,
			"redirect_uri": redirectURI,
		})
	})

	r.GET("/server_resource/email", func(c *gin.Context) {
		code := c.Query("AccessCode")
		cookie := c.Query("cookie")

		if code != oauth2.AccessCode[cookie] {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Unauthorized!")})
			return
		}

		c.JSON(200, gin.H{
			"email": "yolo",
		})
	})

	r.Run() // listen and server on 0.0.0.0:8080}
}
