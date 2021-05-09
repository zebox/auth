package provider

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)

type customLoader struct{}

var test *testing.T

func TestAppleHandler_NewAppleProvider(t *testing.T) {

	cl := customLoader{}
	ah, err := NewAppleProvider(AppleHandler{
		KeyID:            "112233",
		PrivateKeyLoader: cl,
	})
	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

}

// TestAppleHandler_LoadPrivateKey need for testing pre-defined loader from local file
func TestAppleHandler_LoadPrivateKey(t *testing.T) {
	testValidKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`
	testPrivKeyFileName := "privKeyTest.tmp"

	dir, err := ioutil.TempDir(os.TempDir(), testPrivKeyFileName)
	assert.NoError(t, err)
	assert.NotNil(t, dir)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer os.RemoveAll(dir)

	tmpfn := filepath.Join(dir, testPrivKeyFileName)
	if err = ioutil.WriteFile(tmpfn, []byte(testValidKey), 0666); err != nil {
		assert.NoError(t, err)
		log.Fatal(err)
		return
	}

	ah, err := NewAppleProvider(AppleHandler{
		KeyID:            "11223344",
		PrivateKeyLoader: AppleLoadPrivateKeyFromFile(tmpfn),
	})

	assert.NoError(t, err)
	assert.IsType(t, &AppleHandler{}, ah)

	ah, err = NewAppleProvider(AppleHandler{
		KeyID:            "11223344",
		PrivateKeyLoader: AppleLoadPrivateKeyFromFile(testPrivKeyFileName),
	})
	assert.Error(t, err)
}

func (cl customLoader) LoadPrivateKey() ([]byte, error) {

	// valid p8 key
	testValidKey := []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgTxaHXzyuM85Znw7y
SJ9XeeC8gqcpE/VLhZHGsnPPiPagCgYIKoZIzj0DAQehRANCAATnwlOv7I6eC3Ec
/+GeYXT+hbcmhEVveDqLmNcHiXCR9XxJZXtpMRlcRfY8eaJpUdig27dfsbvpnfX5
Ivx5tHkv
-----END PRIVATE KEY-----`)

	//testWrongKey := []byte(`MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJJC+7viVTZtE1yM0IX+Zt8ZNJW6RYLg8fovmEo8AfDo+dvE/ssFSiMSqRcmHhp5y0K+LHAy9QSz8lrIivdPC19LEc9dFUzAM3aCKpVCAbz51OCYRV6/01kyMPiIMYItG1RufF+XJCYHxHZY9JyuheOgGaqmdOIZQmcTwk6r3VYtAgMBAAECgYAuJ5caxiSPxUHr3b/b2NkLo/+VFC/lSijyA1zyaBdQt6RJNtQUqvmnMbdMR8oOHssGp86MJXhuYH6lKU25FyeGEReXIuvoz25z1mLUxbzSAjuWWNq32sfuBx+sYMUMKrt0W0wJrbofRwIElTDaFBXP/arycALT323hWAOp5RKo/QJBAO0tAEBgvq9VqakVHo8pnoN+MFKIQ8pl03zvHWRFmxIsPj1iCO8JeHnRVhr2V8mpHwx+/oHwFDYQWG57FniH8cMCQQCd3sP3EvTwgXctpUNLxfzURZMEOxXEE84iUM2UkrQ4Sb7tJwCEezfIofC7GPQv1yJ8hN9guX0W+lgmiNbScKlPAkBPmkb3VIErf+jNoxT6n9Ff+L5nNOzrxXlR+T84JFSDqO3K1FiDQf55hFUN/5g/Ss/s9cKeAeIGsz269vz3v0jZAkBmlO7vaEEC2o1vepic7xzXbhIWyLHfBCOIxsqfBSjX/otynEpIy6w20YuUd6WMRJXjJY/k0QLIYInRGE/G1HAfAkEAx3UnSl/XLJLXkNawVNhgxWgQWpb7st5rug+MUVqtj3Qtfp55GswBzvHaaMCJOizZc+UjWc4fhRLoi3prBAKAXA==`)

	return testValidKey, nil
}
