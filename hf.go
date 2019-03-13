package hftoken

import (
	"encoding/json"
	"fmt"
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
		panic(fmt.Sprintf("encryptKey should be equal to %d", g_EncryptKeyLength))
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

	return encryptToken, nil
}

func PackageToken(tokenStr string, encryptKey string) (string, error) {
	if len(encryptKey) != g_EncryptKeyLength {
		panic(fmt.Sprintf("[hftoken] PackageToken: encryptKey should be equal to %d", g_EncryptKeyLength))
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
func ParseToken(tokenStr string, encryptKey string, noStrictMode bool) (interface{}, error) {
	if len(encryptKey) != g_EncryptKeyLength {
		panic(fmt.Sprintf("[hftoken] ParseToken: encryptKey should be equal to %d", g_EncryptKeyLength))
	}

	decryptToken := AesDecrypt(tokenStr, encryptKey)

	token := tagToken{}
	err := json.Unmarshal([]byte(decryptToken), &token)
	if err != nil {
		return nil, errors.New("[hftoken] ParseToken: invalid token")
	}

	rcrd, ok := g_mapAuth2User.Load(token.AuthId)
	if !ok {
		return nil, errors.New("[hftoken] ParseToken: invalid token")
	}
	record, ok := rcrd.(*tagRecord)
	if !ok {
		return nil, errors.New("[hftoken] ParseToken: invalid token")
	}
	if token.AuthId != record.AuthId {
		return nil, errors.New("[hftoken] ParseToken: invalid token")
	}

	if noStrictMode != true {
		tNow := time.Now().Unix()
		tOff := tNow - token.ReqTime
		if tOff > 10 || tOff <  0 {
			return nil, errors.New("[hftoken] ParseToken: expired token")
		}
	}

	return record.userdata, nil
}
