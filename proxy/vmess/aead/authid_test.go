package aead

import (
	"fmt"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthIDReplayWithFutureTimestamp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		holder := NewAuthIDDecoderHolder()
		key := [16]byte{1}
		holder.AddUser(key, "user")
		time.Sleep(119 * time.Second)
		authID := CreateAuthID(key[:], time.Now().Unix()+120)
		if _, err := holder.Match(authID); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		holder.CheckReplay([16]byte{2})
		time.Sleep(120 * time.Second)
		holder.CheckReplay([16]byte{3})
		time.Sleep(60 * time.Second)
		if _, err := holder.Match(authID); err != ErrReplay {
			t.Fatal("still-valid captured AuthID lost replay protection", err)
		}
	})
}

func TestCreateAuthID(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)
}

func TestCreateAuthIDAndDecode(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)
}

func TestCreateAuthIDAndDecode2(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test")
	authid2 := CreateAuthID(key2, time.Now().Unix())

	res2, err2 := AuthDecoder.Match(authid2)
	assert.EqualError(t, err2, "user do not exist")
	assert.Nil(t, res2)
}

func TestCreateAuthIDAndDecodeMassive(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	for i := 0; i <= 10000; i++ {
		key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test", strconv.Itoa(i))
		var keyw2 [16]byte
		copy(keyw2[:], key2)
		AuthDecoder.AddUser(keyw2, "Demo User"+strconv.Itoa(i))
	}

	authid3 := CreateAuthID(key, time.Now().Unix())

	res2, err2 := AuthDecoder.Match(authid3)
	assert.Equal(t, "Demo User", res2)
	assert.Nil(t, err2)
}

func TestCreateAuthIDAndDecodeSuperMassive(t *testing.T) {
	key := KDF16([]byte("Demo Key for Auth ID Test"), "Demo Path for Auth ID Test")
	authid := CreateAuthID(key, time.Now().Unix())

	fmt.Println(key)
	fmt.Println(authid)

	AuthDecoder := NewAuthIDDecoderHolder()
	var keyw [16]byte
	copy(keyw[:], key)
	AuthDecoder.AddUser(keyw, "Demo User")
	res, err := AuthDecoder.Match(authid)
	fmt.Println(res)
	fmt.Println(err)
	assert.Equal(t, "Demo User", res)
	assert.Nil(t, err)

	for i := 0; i <= 1000000; i++ {
		key2 := KDF16([]byte("Demo Key for Auth ID Test2"), "Demo Path for Auth ID Test", strconv.Itoa(i))
		var keyw2 [16]byte
		copy(keyw2[:], key2)
		AuthDecoder.AddUser(keyw2, "Demo User"+strconv.Itoa(i))
	}

	authid3 := CreateAuthID(key, time.Now().Unix())

	before := time.Now()
	res2, err2 := AuthDecoder.Match(authid3)
	after := time.Now()
	assert.Equal(t, "Demo User", res2)
	assert.Nil(t, err2)

	fmt.Println(after.Sub(before).Seconds())
}
