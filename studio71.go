package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GetTokenResp struct {
	Token     string `json:"access_token"`
	Type      string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

type CheckTokenResp struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"msg"`
	} `json:"error"`
	User struct {
		ID int `json:"id"`
	} `json:"auth_user"`
	Client struct {
		ID int `json:"id"`
	} `json:"auth_client"`
}

func GetS71Token(code string) (string, error) {
	postData := url.Values{}
	postData.Set("code", code)
	postData.Set("client_id", GetConfigString("studio71_client_id"))
	postData.Set("client_secret", GetConfigString("studio71_client_secret"))
	postData.Set("redirect_uri", GetConfigString("studio71_redirect_uri"))
	postData.Set("grant_type", "authorization_code")

	data, err := apiReq("/auth/token", "post", postData, "")
	if err != nil {
		return "", err
	}

	tokenResp := GetTokenResp{}
	err = json.Unmarshal(data, &tokenResp)
	if err != nil {
		return "", err
	}

	if tokenResp.Token != "" {
		return tokenResp.Token, nil
	}

	return "", errors.New("Unable to obtain Studio71 token.")
}

func VerifyS71Token(token string) bool { // /me
	data, err := apiReq("/auth/dump?apikey="+GetConfigString("studio71_client_id"), "get", url.Values{}, token)
	if err != nil {
		return false
	}

	tokenDump := CheckTokenResp{}
	err = json.Unmarshal(data, &tokenDump)
	if err != nil {
		return false
	}

	if tokenDump.User.ID > 0 {
		return true
	}

	return false
}

func apiReq(path string, method string, data url.Values, token string) ([]byte, error) {
	client := http.Client{
		Timeout: time.Second * 5, // Maximum of 2 secs
	}

	url := fmt.Sprintf("https://api.studio71.io%s", path)
	req := &http.Request{}
	var err error

	if method == "get" {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return []byte{}, err
		}
	} else if method == "post" {
		req, err = http.NewRequest(http.MethodPost, url, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		err := errors.New("Method not supported by Studio71 API client.")
		return []byte{}, err
	}

	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	res, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}
