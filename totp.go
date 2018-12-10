package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

func truncate(hs []byte) int {
	offset := hs[len(hs)-1] & 0x0f
	return ((int)(hs[offset]&0x7f) << 24) + ((int)(hs[offset+1]&0xff) << 16) + ((int)(hs[offset+2]&0xff) << 8) + (int)(hs[offset+3]&0xff)
}

func generateHOTP(key []byte, couter []byte, crypto func() hash.Hash, modulo int) ([]byte, int) {
	mac := hmac.New(crypto, key)
	mac.Write(couter)
	hashString := mac.Sum(nil)
	return hashString, (truncate(hashString) % modulo)
}

func generateTOTP(key []byte, unixTime int64, crypto func() hash.Hash, modulo int) int {
	count := int2count(uint(unixTime / 30))
	_, ret := generateHOTP(key, count[:], crypto, modulo)
	return ret
}

func int2count(num uint) [8]byte {
	var ret [8]byte
	for i := 0; i < 8; i++ {
		ret[8-i-1] = byte(num & 0xff)
		num = num >> 8
	}
	return ret
}

func main() {

	app := cli.NewApp()
	app.Name = "totp"
	app.Usage = "generate time-based one-time password"
	app.Action = func(c *cli.Context) error {
		fmt.Println("Start TOTP Test")

		key_sha1 := ([]byte)("12345678901234567890")
		key_sha256 := ([]byte)("12345678901234567890123456789012")
		key_sha512 := ([]byte)("1234567890123456789012345678901234567890123456789012345678901234")
		keys := []([]byte){key_sha1, key_sha256, key_sha512}
		hashNames := []string{"SHA-1", "SHA256", "SHA512"}
		times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
		cryptos := [](func() hash.Hash){sha1.New, sha256.New, sha512.New}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Time (sec)", "Time", "TOTP", "Mode"})
		for _, t := range times {
			for i, crypto := range cryptos {
				totp := generateTOTP(keys[i], t, crypto, 100000000)
				table.Append([]string{fmt.Sprintf("%d", t), fmt.Sprintf("%v", time.Unix(t, 0)), fmt.Sprintf("%08d", totp), fmt.Sprintf("%s", hashNames[i])})
			}
		}
		table.Render()

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
