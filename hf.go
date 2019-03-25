package hftoken

import (
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sync"
	"sync/atomic"
	"time"
)

type tagToken struct {
	AuthId		uint64
	ReqTime		int64
}

type tagRecord struct {
	*tagToken
	userdata		interface{}
}

var g_AuthIDSeed uint64
var g_mapAuth2User sync.Map
const g_EncryptKeyLength = 16

func GenerateToken(userdata interface{}, encryptKey string) (string, error) {
	if len(encryptKey) != g_EncryptKeyLength {
		errMsg := fmt.Sprintf("[hftoken] GenerateToken: encryptKey should be equal to %d", g_EncryptKeyLength)
		glog.Error(errMsg)
		return "", errors.New(errMsg)
	}

	//unique id for each auth user
	authId := atomic.AddUint64(&g_AuthIDSeed, 1)
	token := tagToken{
		AuthId: authId,
		ReqTime: 0,
	}
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	tokenStr := string(tokenBytes)
	encryptToken := AesEncrypt(tokenStr, encryptKey)

	record := tagRecord{
		tagToken:	&token,
		userdata:	userdata,
	}
	g_mapAuth2User.Store(authId, &record)
	glog.Info("[hftoken] GenerateToken: ", authId, token, userdata)

	return encryptToken, nil
}

func PackageToken(tokenStr string, encryptKey string) (string, error) {
	if len(encryptKey) != g_EncryptKeyLength {
		errMsg := fmt.Sprintf("[hftoken] PackageToken: encryptKey should be equal to %d", g_EncryptKeyLength)
		glog.Error(errMsg)
		return "", errors.New(errMsg)
	}

	decryptToken := AesDecrypt(tokenStr, encryptKey)

	token := tagToken{}
	err := json.Unmarshal([]byte(decryptToken), &token)
	if err != nil {
		return "", err
	}

	token.ReqTime = time.Now().Unix()
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	tokenStr = string(tokenBytes)
	encryptToken := AesEncrypt(tokenStr, encryptKey)
	return encryptToken, nil
}

//length encryptKey should be equal to 16
func ServerParseToken(tokenStr string, encryptKey string, noStrictMode bool) (interface{}, error) {
	if len(encryptKey) != g_EncryptKeyLength {
		errMsg := fmt.Sprintf("[hftoken] ServerParseToken: encryptKey should be equal to %d", g_EncryptKeyLength)
		glog.Error(errMsg)
		return "", errors.New(errMsg)
	}

	decryptToken := AesDecrypt(tokenStr, encryptKey)

	token := tagToken{}
	err := json.Unmarshal([]byte(decryptToken), &token)
	if err != nil {
		glog.Error("[hftoken] ServerParseToken: invalid token", decryptToken)
		return nil, errors.New("[hftoken] ServerParseToken: invalid token")
	}

	rcrd, ok := g_mapAuth2User.Load(token.AuthId)
	if !ok {
		glog.Error("[hftoken] ServerParseToken: invalid token", token.AuthId)
		return nil, errors.New("[hftoken] ServerParseToken: invalid token")
	}
	record, ok := rcrd.(*tagRecord)
	if !ok {
		glog.Error("[hftoken] ServerParseToken: invalid token", rcrd)
		return nil, errors.New("[hftoken] ServerParseToken: invalid token")
	}
	if token.AuthId != record.AuthId {
		glog.Error("[hftoken] ServerParseToken: invalid token", token.AuthId, record.AuthId)
		return nil, errors.New("[hftoken] ServerParseToken: invalid token")
	}

	if noStrictMode != true {
		tNow := time.Now().Unix()
		tOff := tNow - token.ReqTime
		if tOff > 10 || tOff <  0 {
			glog.Warning("[hftoken] ServerParseToken: expired token", tNow, token.ReqTime)
			return nil, errors.New("[hftoken] ServerParseToken: expired token")
		}
	}

	return record.userdata, nil
}

//length encryptKey should be equal to 16
func ClientParseToken(tokenStr string, encryptKey string) error {
	if len(encryptKey) != g_EncryptKeyLength {
		errMsg := fmt.Sprintf("[hftoken] ClientParseToken: encryptKey should be equal to %d", g_EncryptKeyLength)
		glog.Error(errMsg)
		return errors.New(errMsg)
	}

	decryptToken := AesDecrypt(tokenStr, encryptKey)

	token := tagToken{}
	err := json.Unmarshal([]byte(decryptToken), &token)
	if err != nil {
		return errors.New("[hftoken] ClientParseToken: invalid token")
	}

	return nil
}
